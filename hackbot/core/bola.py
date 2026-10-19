"""
HackBot Advanced BOLA / IDOR
============================
Ownership-aware object-ID substitution on top of the differential engine.

For every corpus request in which identity **A** sends an object ID that
the ownership ledger says A owns, HackBot builds substitution cases that put
identity **B**'s object of the *same type* in its place, then:

1. sends the modified request as **B** (fresh baseline: B reading its own
   object must show B's markers, otherwise the endpoint can't prove
   anything);
2. sends the same modified request as **A** and judges it with the shared
   differential logic — ``exposed`` only when B's marker comes back.

Mutations (bounded, one victim object per type and victim):

* ``replace``            the ID in its original location
* ``pollution_last`` /   ``id=A&id=B`` / ``id=B&id=A`` (query and form)
  ``pollution_first``
* ``type_juggle``        JSON ``123`` ↔ ``"123"``
* ``array_wrap``         JSON ``[123]``

Only victim IDs from the ledger are ever used — never guessed IDs that may
belong to real users. Non-GET cases go through the escalation gate (human
approval) like every other state-changing request.

ID predictability is classified per parameter so the report states the
attack complexity honestly (sequential IDs → AC:L; random UUIDv4 / opaque
tokens → AC:H, the victim ID must leak elsewhere).
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from hackbot.core.authz_diff import SAFE_METHODS, AuthzDiff, Response, Variant
from hackbot.core.corpus import Corpus, Exchange, Param, value_type
from hackbot.core.identities import ANONYMOUS, IdentityVault

MAX_CASES = 30


# ── ID predictability ────────────────────────────────────────────────────────


@dataclass
class Predictability:
    kind: str
    attack_complexity: str  # L | H
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "attack_complexity": self.attack_complexity,
                "reason": self.reason}

    def note(self) -> str:
        return f"Object ID: {self.kind} → AC:{self.attack_complexity} ({self.reason})"


def _objectid_time(value: str) -> Optional[_dt.datetime]:
    if len(value) != 24:
        return None
    try:
        ts = int(value[:8], 16)
    except ValueError:
        return None
    t = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    return t if 2009 <= t.year <= 2040 else None


def classify_ids(values: List[str]) -> Predictability:
    vals = [str(v) for v in values if str(v)]
    if not vals:
        return Predictability("unknown", "H", "no sample values")
    types = {value_type(v) for v in vals}
    if types == {"int"}:
        nums = sorted({int(v) for v in vals})
        if len(nums) >= 2 and nums[-1] - nums[0] <= max(1000, len(nums) * 100):
            return Predictability("sequential integer", "L",
                                  f"{len(nums)} observed values within {nums[-1] - nums[0]} "
                                  "of each other — enumerable")
        return Predictability("integer", "L",
                              "integers are usually enumerable; sequence not confirmed "
                              f"({len(nums)} sample(s))")
    if types == {"uuid"}:
        versions = {v[14] for v in vals}
        if versions == {"4"}:
            return Predictability("random UUIDv4", "H",
                                  "not guessable — the victim's ID must leak elsewhere "
                                  "(list endpoint, share link, notification…)")
        if versions <= {"1", "6", "7"}:
            return Predictability(f"time-based UUIDv{'/'.join(sorted(versions))}", "L",
                                  "embeds a timestamp; neighbouring IDs are predictable")
        return Predictability("UUID", "H", f"versions {sorted(versions)}")
    if types == {"hex"}:
        if all(_objectid_time(v) for v in vals):
            return Predictability("MongoDB ObjectId", "L",
                                  "timestamp + counter; IDs created close in time are "
                                  "partially predictable")
        return Predictability(f"opaque hex ({max(len(v) for v in vals)} chars)", "H",
                              "not guessable — the victim's ID must leak elsewhere")
    if types == {"email"}:
        return Predictability("email address", "L", "emails are often known or guessable")
    return Predictability("opaque token", "H", "not guessable — the victim's ID must leak "
                          "elsewhere")


# ── Request mutation ─────────────────────────────────────────────────────────


def _set_json_path(obj: Any, path: str, value: Any) -> bool:
    """Set a flattened corpus path (``a.b``, ``items[].id``) in *obj*."""
    parts = path.replace("[]", ".[]").split(".")
    parts = [p for p in parts if p]

    def walk(node: Any, i: int) -> bool:
        key = parts[i]
        last = i == len(parts) - 1
        if key == "[]":
            if not isinstance(node, list) or not node:
                return False
            if last:
                node[0] = value
                return True
            return walk(node[0], i + 1)
        if not isinstance(node, dict) or key not in node:
            return False
        if last:
            node[key] = value
            return True
        return walk(node[key], i + 1)

    return walk(obj, 0)


def _json_value(original: str, new: str, mode: str) -> Any:
    """The JSON value to place, keeping the original's JSON type unless juggling."""
    is_int = value_type(new) == "int"
    if mode == "array_wrap":
        return [int(new) if is_int else new]
    if mode == "type_juggle":
        return new if isinstance(original, int) else (int(new) if is_int else new)
    return int(new) if isinstance(original, int) and is_int else new


def mutate(ex: Exchange, param: Param, victim_value: str, mode: str) -> Optional[Exchange]:
    """A copy of *ex* with *param* pointing at *victim_value* (None if not applicable)."""
    parts = urlsplit(ex.url)
    if param.location == "path":
        if mode != "replace":
            return None
        segs = parts.path.split("/")
        idx = int(param.name.rsplit("#", 1)[1])
        if idx >= len(segs) or segs[idx] != param.value:
            return None
        segs[idx] = victim_value
        path = "/".join(segs)
        return replace(ex, url=urlunsplit(parts._replace(path=path)), path=path)

    if param.location in ("query", "body"):
        source = parts.query if param.location == "query" else ex.request_body
        pairs = parse_qsl(source, keep_blank_values=True)
        if mode == "replace":
            pairs = [(k, victim_value if k == param.name else v) for k, v in pairs]
        elif mode == "pollution_last":
            pairs = pairs + [(param.name, victim_value)]
        elif mode == "pollution_first":
            pairs = [(param.name, victim_value)] + pairs
        else:
            return None
        encoded = urlencode(pairs)
        if param.location == "query":
            return replace(ex, url=urlunsplit(parts._replace(query=encoded)))
        return replace(ex, request_body=encoded)

    if param.location == "json":
        if mode not in ("replace", "type_juggle", "array_wrap"):
            return None
        try:
            body = json.loads(ex.request_body)
        except ValueError:
            return None
        original = _get_json(body, param.name)
        if original is None:
            return None
        new_body = copy.deepcopy(body)
        if not _set_json_path(new_body, param.name, _json_value(original, victim_value, mode)):
            return None
        return replace(ex, request_body=json.dumps(new_body))
    return None


def _get_json(obj: Any, path: str) -> Any:
    node = obj
    for key in [p for p in path.replace("[]", ".[]").split(".") if p]:
        if key == "[]":
            if not isinstance(node, list) or not node:
                return None
            node = node[0]
        elif isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return node


MODES = {
    "path": ("replace",),
    "query": ("replace", "pollution_last", "pollution_first"),
    "body": ("replace", "pollution_last", "pollution_first"),
    "json": ("replace", "type_juggle", "array_wrap"),
}


# ── Planning + execution ─────────────────────────────────────────────────────


@dataclass
class Case:
    exchange_id: int
    attacker: str
    victim: str
    obj_type: str
    param: str
    location: str
    attacker_value: str
    victim_value: str
    mode: str
    request: Exchange
    predictability: Predictability
    baseline: Optional[Variant] = None
    attack: Optional[Variant] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exchange_id": self.exchange_id, "attacker": self.attacker, "victim": self.victim,
            "obj_type": self.obj_type, "param": self.param, "location": self.location,
            "attacker_value": self.attacker_value, "victim_value": self.victim_value,
            "mode": self.mode, "method": self.request.method, "url": self.request.url,
            "predictability": self.predictability.to_dict(),
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "attack": self.attack.to_dict() if self.attack else None,
        }


@dataclass
class BolaReport:
    cases: List[Case] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"cases": [c.to_dict() for c in self.cases], "skipped": self.skipped}


class BolaTester:
    def __init__(self, corpus: Corpus, vault: IdentityVault,
                 execute: Callable[[str, str], Tuple[int, str]]):
        self.corpus = corpus
        self.vault = vault
        self.diff = AuthzDiff(corpus, vault, execute)
        self.execute = execute

    def _predictability(self, ex: Exchange, param: Param, obj_type: str) -> Predictability:
        values = [p.value for e in self.corpus.exchanges if e.template == ex.template
                  for p in e.params if p.name == param.name and p.value]
        for ident in self.vault.identities.values():
            values += ident.owned.get(obj_type, [])
        return classify_ids(values)

    def plan(self, exchange_id: Optional[int] = None, max_cases: int = MAX_CASES,
             modes: Optional[List[str]] = None) -> BolaReport:
        report = BolaReport()
        exchanges = [self.corpus.get(exchange_id)] if exchange_id else self.corpus.exchanges
        seen = set()
        for ex in exchanges:
            if ex is None:
                report.skipped.append(f"no exchange #{exchange_id}")
                continue
            attacker = ex.identity
            if attacker in ("", ANONYMOUS) or attacker not in self.vault.identities:
                report.skipped.append(f"#{ex.id}: sender is not a vault identity")
                continue
            owned_by_attacker = self.vault.get(attacker).owned
            for param in ex.params:
                if not param.is_id_candidate or not param.value:
                    continue
                obj_type = next((t for t, ids in owned_by_attacker.items()
                                 if param.value in ids), "")
                if not obj_type:
                    report.skipped.append(
                        f"#{ex.id} {param.location}:{param.name}={param.value}: not an object "
                        f"{attacker} owns in the ledger")
                    continue
                pred = self._predictability(ex, param, obj_type)
                for victim in self.vault.identities.values():
                    if victim.name in (attacker, ANONYMOUS) or not victim.markers:
                        continue
                    victim_ids = victim.owned.get(obj_type, [])
                    if not victim_ids:
                        continue
                    for mode in MODES.get(param.location, ()):
                        if modes and mode not in modes:
                            continue
                        key = (ex.method, ex.template, param.name, mode, victim.name)
                        if key in seen:
                            continue
                        req = mutate(ex, param, victim_ids[0], mode)
                        if req is None:
                            continue
                        seen.add(key)
                        report.cases.append(Case(
                            ex.id, attacker, victim.name, obj_type, param.name,
                            param.location, param.value, victim_ids[0], mode, req, pred))
                        if len(report.cases) >= max_cases:
                            report.skipped.append(f"case limit {max_cases} reached")
                            return report
        return report

    def run(self, report: BolaReport) -> BolaReport:
        baselines: Dict[Tuple[int, str, str], Tuple[Variant, Response]] = {}
        for case in report.cases:
            key = (case.exchange_id, case.param, case.victim)
            if key not in baselines:
                # Baseline: the victim requesting its own object (plain replace form).
                plain = next((c.request for c in report.cases
                              if (c.exchange_id, c.param, c.victim) == key and c.mode == "replace"),
                             case.request)
                base = Variant(identity=case.victim,
                               command=self.diff.build_command(plain, case.victim))
                base.step, raw = self.execute(base.command,
                                              f"BOLA baseline: {case.victim} reads own "
                                              f"{case.obj_type} {case.victim_value}")
                resp = Response.parse(raw)
                base.status = resp.status
                if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
                    base.verdict, base.detail = "blocked", raw.strip()[:300]
                else:
                    markers = self.vault.get(case.victim).markers
                    base.owner_marker = next((m for m in markers if m in resp.body), "")
                    base.verdict = "baseline" if base.owner_marker else "no_marker"
                    if not base.owner_marker:
                        base.detail = (f"{case.victim}'s own response has none of its markers "
                                       "— exposure can't be proven on this endpoint")
                baselines[key] = (base, resp)
            base, base_resp = baselines[key]
            case.baseline = base
            if base.verdict != "baseline":
                continue
            attack = Variant(identity=case.attacker,
                             command=self.diff.build_command(case.request, case.attacker))
            attack.step, raw = self.execute(
                attack.command,
                f"BOLA {case.mode}: {case.attacker} requests {case.victim}'s "
                f"{case.obj_type} {case.victim_value} via {case.location}:{case.param}")
            self.diff.judge(attack, raw, base_resp.body, case.victim,
                            [m for m in self.vault.get(case.victim).markers if m])
            case.attack = attack
        return report

    def finding_actions(self, report: BolaReport) -> List[Dict[str, Any]]:
        out = []
        for c in report.cases:
            a = c.attack
            if a is None or a.verdict != "exposed" or a.step is None or not a.excerpt:
                continue
            ex = self.corpus.get(c.exchange_id)
            template = ex.template if ex else c.request.path
            attacker, victim = self.vault.get(c.attacker), self.vault.get(c.victim)
            cross_tenant = attacker.tenant and victim.tenant and attacker.tenant != victim.tenant
            write = c.request.method not in SAFE_METHODS
            out.append({
                "action": "finding",
                "title": f"IDOR: {c.request.method} {template} — {c.location} {c.param} "
                         f"({c.mode}) exposes another user's {c.obj_type}",
                "severity": "Medium",
                "vuln_class": "idor",
                "asset": c.request.url,
                "behavior": (f"{c.attacker} sent {c.request.method} {c.request.url} with "
                             f"{c.location} parameter {c.param} set to {c.victim}'s "
                             f"{c.obj_type} {c.victim_value} ({c.mode}); the response "
                             f"(HTTP {a.status}, step {a.step}) contains {c.victim}'s marker "
                             f"{a.owner_marker!r}. Baseline: {c.victim} reading its own object "
                             f"was step {c.baseline.step if c.baseline else '?'}."),
                "boundary": ("tenant isolation between customer accounts" if cross_tenant
                             else "object-level authorization between two accounts"),
                # Only what was observed: B's data came back. A state change is never
                # claimed from a response alone.
                "impact": (f"{c.attacker} received {c.victim}'s {c.obj_type} "
                           f"{c.victim_value} data ({a.owner_marker}) in the response"
                           + (f"; whether the {c.request.method} also changed {c.victim}'s "
                              "object was not verified" if write else "")),
                "evidence_refs": [{"step": a.step, "excerpt": a.excerpt, "supports": "both"}],
                "reproduction": (f"baseline (victim): {c.baseline.command if c.baseline else ''}\n"
                                 f"attack: {a.command}"),
                "attacker_identity": c.attacker,
                "victim_identity": c.victim,
                "victim_identifier": a.owner_marker,
                "privileges_required": attacker.role,
                "description": (f"{c.predictability.note()}. Found by ownership-aware ID "
                                "substitution; only hunter-owned test objects were used. "
                                "Severity is a placeholder — set it from the data exposed."),
            })
        return out
