"""
HackBot Differential Authorization Replay
=========================================
The core primitive for BOLA / IDOR / BFLA testing:

1. take an exchange from the corpus that belongs to identity **owner**;
2. re-send it as the owner (fresh baseline, captured by HackBot itself);
3. re-send the *same* request as each other identity (other user, lower
   role, anonymous) — only the credentials change;
4. compare each response with the baseline and look for the owner's
   **markers** (email, user id … from the identity vault).

Requests are built as ``curl`` commands with ``{{cookie|bearer|header:…}}``
placeholders and executed through the ToolRunner, so scope enforcement,
the escalation gate, human approvals and credential redaction all apply,
and every response becomes an agent step the proof gate can cite.

Safety:

* GET / HEAD / OPTIONS replay automatically.
* Any other method is only planned when every object ID in the request is
  in the ownership ledger (a hunter-owned test object); it then still goes
  through the escalation gate, i.e. it needs a human "yes".

A variant is only reported as ``exposed`` when the owner's marker appears
in the other identity's 2xx response — never on status codes alone.
"""

from __future__ import annotations

import difflib
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from hackbot.core.corpus import Corpus, Exchange
from hackbot.core.identities import ANONYMOUS, IdentityVault

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
_SKIP_HEADERS = {"cookie", "authorization", "host", "content-length", "connection",
                 "accept-encoding", "proxy-connection"}
_DYNAMIC_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?|"  # ISO timestamps
    r"\b1[5-9]\d{8,11}\b|"                                                  # epoch s / ms
    r"\b[0-9a-f]{32,}\b",                                                   # nonces / etags
    re.I)
_DENIED_RE = re.compile(r"unauthori[sz]ed|forbidden|access denied|not allowed|"
                        r"permission denied|login required|<input[^>]+type=[\"']?password", re.I)


@dataclass
class Response:
    status: int
    headers: str
    body: str

    @classmethod
    def parse(cls, raw: str) -> "Response":
        """Parse ``curl -s -i`` output (last response block wins)."""
        blocks = re.split(r"(?m)^(?=HTTP/[\d.]+ \d{3})", raw)
        block = next((b for b in reversed(blocks) if b.startswith("HTTP/")), "")
        if not block:
            return cls(0, "", raw)
        head, _, body = block.replace("\r\n", "\n").partition("\n\n")
        m = re.match(r"HTTP/[\d.]+ (\d{3})", head)
        return cls(int(m.group(1)) if m else 0, head, body)


@dataclass
class Variant:
    identity: str
    command: str
    step: Optional[int] = None
    status: int = 0
    similarity: float = 0.0
    owner_marker: str = ""
    excerpt: str = ""
    verdict: str = "not_run"  # exposed | same_as_baseline | denied | different | blocked
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class DiffPlan:
    exchange_id: int
    owner: str
    method: str
    url: str
    template: str
    baseline: Variant
    variants: List[Variant] = field(default_factory=list)
    refused: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"exchange_id": self.exchange_id, "owner": self.owner, "method": self.method,
                "url": self.url, "template": self.template, "refused": self.refused,
                "baseline": self.baseline.to_dict(),
                "variants": [v.to_dict() for v in self.variants]}


def normalize(body: str) -> str:
    return re.sub(r"\s+", " ", _DYNAMIC_RE.sub("", body or "")).strip()


def similarity(a: str, b: str) -> float:
    a, b = normalize(a), normalize(b)
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def _excerpt(text: str, needle: str, width: int = 60) -> str:
    """A verbatim, single-line slice of *text* around *needle*."""
    i = text.find(needle)
    if i < 0:
        return ""
    start = max(0, text.rfind("\n", 0, i) + 1, i - width)
    end = text.find("\n", i)
    end = min(len(text) if end < 0 else end, i + len(needle) + width)
    return text[start:end].strip()


class AuthzDiff:
    def __init__(self, corpus: Corpus, vault: IdentityVault,
                 execute: Callable[[str, str], Tuple[int, str]]):
        """``execute(command, explanation) -> (step number, redacted output)``."""
        self.corpus = corpus
        self.vault = vault
        self.execute = execute

    # ── planning ─────────────────────────────────────────────────────────
    def _auth_args(self, identity: str) -> List[str]:
        if identity == ANONYMOUS:
            return []
        ident = self.vault.get(identity)
        args: List[str] = []
        if ident.cookies:
            args += ["-H", f"Cookie: {{{{cookie:{identity}}}}}"]
        if ident.bearer:
            args += ["-H", f"Authorization: Bearer {{{{bearer:{identity}}}}}"]
        for name in ident.headers:
            args += ["-H", f"{name}: {{{{header:{identity}:{name}}}}}"]
        return args

    def build_command(self, ex: Exchange, identity: str) -> str:
        args = ["curl", "-s", "-i", "--max-time", "20", "-X", ex.method]
        for k, v in ex.request_headers.items():
            if k.lower() in _SKIP_HEADERS or "<redacted:" in v:
                continue
            args += ["-H", f"{k}: {v}"]
        args += self._auth_args(identity)
        if ex.request_body and ex.method not in ("GET", "HEAD"):
            args += ["--data-raw", ex.request_body]
        args.append(ex.url)
        return " ".join(shlex.quote(a) for a in args)

    def plan(self, exchange_id: int, identities: Optional[List[str]] = None) -> DiffPlan:
        ex = self.corpus.get(exchange_id)
        if ex is None:
            raise ValueError(f"no exchange #{exchange_id} in the corpus")
        owner = ex.identity
        empty = Variant(identity=owner or "?", command="")
        plan = DiffPlan(exchange_id, owner, ex.method, ex.url, ex.template, empty)
        if not owner or owner == ANONYMOUS or owner not in self.vault.identities:
            plan.refused = ("exchange is not attributed to a vault identity — the owner must be "
                            "a known test account so its data can be recognised")
            return plan
        if not self.vault.get(owner).markers:
            plan.refused = f"identity {owner!r} has no markers to recognise its data"
            return plan
        if ex.method not in SAFE_METHODS:
            ids = [p.value for p in ex.params if p.is_id_candidate and p.value]
            foreign = [i for i in ids if self.vault.owner_of(i) is None]
            if not ids or foreign:
                plan.refused = (f"{ex.method} is state-changing and the request's object IDs "
                                f"{foreign or '(none found)'} are not in the ownership ledger — "
                                "only hunter-owned test objects may be modified")
                return plan
        plan.baseline = Variant(identity=owner, command=self.build_command(ex, owner))
        others = identities or [n for n in self.vault.names() if n != owner]
        for name in others:
            if name == owner:
                continue
            self.vault.get(name)  # raises on unknown identities
            plan.variants.append(Variant(identity=name, command=self.build_command(ex, name)))
        return plan

    # ── execution + comparison ───────────────────────────────────────────
    def run(self, plan: DiffPlan) -> DiffPlan:
        if plan.refused:
            return plan
        markers = [m for m in self.vault.get(plan.owner).markers if m]
        base = plan.baseline
        base.step, raw = self.execute(base.command, f"authz baseline as {plan.owner}")
        if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
            base.verdict, base.detail = "blocked", raw.strip()[:300]
            plan.refused = "baseline request was blocked"
            return plan
        base_resp = Response.parse(raw)
        base.status = base_resp.status
        base.owner_marker = next((m for m in markers if m in base_resp.body), "")
        base.verdict = "baseline"
        if not base.owner_marker:
            base.detail = ("owner markers not in the baseline response — this endpoint "
                           "doesn't return the owner's data, so exposure can't be proven here")

        for v in plan.variants:
            v.step, raw = self.execute(v.command, f"authz replay as {v.identity}")
            if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
                v.verdict, v.detail = "blocked", raw.strip()[:300]
                continue
            resp = Response.parse(raw)
            v.status = resp.status
            v.similarity = round(similarity(base_resp.body, resp.body), 3)
            # Markers of the requesting identity itself don't count (own data).
            own = set(self.vault.get(v.identity).markers)
            marker = next((m for m in markers if m not in own and m in resp.body), "")
            if 200 <= resp.status < 300 and marker:
                v.verdict, v.owner_marker = "exposed", marker
                v.excerpt = _excerpt(resp.body, marker)
                v.detail = f"{v.identity} received {plan.owner}'s marker {marker!r}"
            elif resp.status in (401, 403, 404, 405) or (
                    300 <= resp.status < 400) or _DENIED_RE.search(resp.body[:2000]):
                v.verdict, v.detail = "denied", f"HTTP {resp.status}"
            elif 200 <= resp.status < 300 and v.similarity >= 0.9:
                v.verdict = "same_as_baseline"
                v.detail = ("2xx and ≥90% similar to the owner's response, but no owner marker "
                            "— a lead, not proof")
            else:
                v.verdict, v.detail = "different", f"HTTP {resp.status}, similarity {v.similarity}"
        return plan

    # ── finding drafts (facts only) ──────────────────────────────────────
    def finding_actions(self, plan: DiffPlan) -> List[Dict[str, Any]]:
        """Finding actions for every exposed variant, built only from observed facts."""
        out = []
        owner = self.vault.get(plan.owner) if plan.owner in self.vault.identities else None
        for v in plan.variants:
            if v.verdict != "exposed" or v.step is None or not v.excerpt:
                continue
            attacker = self.vault.get(v.identity)
            same_role = owner is not None and attacker.role == owner.role
            cross_tenant = owner is not None and owner.tenant and attacker.tenant and \
                owner.tenant != attacker.tenant
            if v.identity == ANONYMOUS:
                cls, boundary = "auth bypass", "authentication on this endpoint"
            elif same_role:
                cls = "idor"
                boundary = ("tenant isolation between customer accounts" if cross_tenant
                            else "object-level authorization between two accounts of the same role")
            else:
                cls, boundary = "bfla", (f"function-level authorization between roles "
                                         f"{attacker.role!r} and {owner.role if owner else '?'!r}")
            out.append({
                "action": "finding",
                "title": f"{cls.upper()}: {plan.method} {plan.template} returns "
                         f"{plan.owner}'s data to {v.identity}",
                "severity": "Medium",
                "vuln_class": cls,
                "asset": plan.url,
                "behavior": (f"{plan.method} {plan.url} sent with {v.identity}'s credentials "
                             f"returned HTTP {v.status} containing {plan.owner}'s marker "
                             f"{v.owner_marker!r} (step {v.step}); baseline as {plan.owner} "
                             f"was step {plan.baseline.step}"),
                "boundary": boundary,
                "impact": (f"{v.identity} read {plan.owner}'s data ({v.owner_marker}) "
                           f"from {plan.template}"),
                "evidence_refs": [{"step": v.step, "excerpt": v.excerpt, "supports": "both"}],
                "reproduction": f"baseline: {plan.baseline.command}\nattack: {v.command}",
                "attacker_identity": v.identity,
                "victim_identity": plan.owner,
                "victim_identifier": v.owner_marker,
                "privileges_required": "none" if v.identity == ANONYMOUS else attacker.role,
                "description": "Recorded by the differential authorization engine. "
                               "Severity is a placeholder — set it from the data exposed.",
            })
        return out
