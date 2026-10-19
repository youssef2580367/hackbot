"""
HackBot Proof Gate
==================
Decides whether a finding is CONFIRMED or stays an unverified LEAD.

A finding is CONFIRMED only when all three pillars are stated *and* backed
by evidence HackBot can verify itself:

1. **behavior**  — what technically happened (the observed response/output).
2. **boundary**  — which security boundary was crossed (e.g. object-level
   authorization between two users, authentication, tenant isolation).
3. **impact**    — what an attacker actually obtained or did, stated as a
   demonstrated fact (speculative wording such as "could"/"may" fails).

Evidence is never taken on the AI's word. Every cited excerpt must appear in

* the captured stdout/stderr of a command HackBot itself ran during the
  assessment (``observed``), or
* a human-attested recorded artifact — Burp request/response, HAR, raw HTTP
  dump, screenshot — whose bytes are hashed at attestation time
  (``recorded``). This is the path for state-changing or dangerous proofs:
  they are performed once by the human (or with explicit approval) and the
  recording is attested, instead of being automatically replayed.

Vulnerability classes whose impact cannot be seen in tool output (e.g. XSS
execution in a browser, CSRF, clickjacking) additionally require a recorded,
human-attested artifact.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class Verification(str, Enum):
    LEAD = "lead"            # unverified discovery — never reported as a vuln
    CONFIRMED = "confirmed"  # all pillars backed by verified evidence


MIN_EXCERPT_LEN = 8

# Speculative / theoretical phrasing that is not a demonstrated impact.
SPECULATIVE_RE = re.compile(
    r"\b(could|may|might|potentially|possibl[ey]|likely|theoretical(ly)?|"
    r"would (allow|lead|enable)|can lead|could lead|if an attacker|in theory)\b",
    re.I,
)

# Classes whose impact is not observable in captured tool output alone.
REQUIRES_RECORDED_PROOF: Dict[str, str] = {
    "xss": "script execution must be shown in a browser (screenshot/HAR of the payload firing "
           "in the target origin)",
    "csrf": "a cross-origin request must be shown changing the victim's state "
            "(recorded PoC page + resulting state)",
    "clickjacking": "a working framed PoC on a sensitive action must be recorded",
    "race condition": "the duplicated effect (e.g. double redemption) must be recorded",
    "business logic": "the end state proving the abuse (balance, order, entitlement) "
                      "must be recorded",
    "session management": "the lifecycle event itself (password change / logout / role "
                          "change) must be recorded so the before → event → after timeline "
                          "is provable",
}

_CLASS_KEYWORDS = {
    "xss": ("xss", "cross-site scripting", "cross site scripting"),
    "csrf": ("csrf", "cross-site request forgery", "xsrf"),
    "clickjacking": ("clickjacking", "ui redress"),
    "race condition": ("race condition", "toctou"),
    "business logic": ("business logic",),
    "session management": ("session management", "session not invalidated",
                           "not invalidated after", "privileges not revoked"),
}


def detect_class(title: str, vuln_class: str = "") -> str:
    """Best-effort vulnerability class from an explicit class or the title."""
    text = f"{vuln_class} {title}".lower()
    for cls, words in _CLASS_KEYWORDS.items():
        if any(w in text for w in words):
            return cls
    return vuln_class.strip().lower()


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


# ── Evidence sources ─────────────────────────────────────────────────────────


# Tools whose output is whatever the agent asked them to print. Their output
# is never evidence (``echo "IDOR confirmed"`` proves nothing).
NON_EVIDENCE_TOOLS = frozenset({
    "echo", "printf", "cat", "tee", "head", "tail", "less", "more", "type",
    "write-output", "print", "yes", "sed", "awk", "tr", "cut", "sort", "uniq",
    "base64", "xxd", "rev",
})

_INTERPRETERS = ("python", "python3", "ruby", "perl", "node", "bash", "sh", "php")


@dataclass
class Observation:
    """Output HackBot captured from a command it actually executed.

    ``generated_text`` is text the agent itself authored for this command
    (the command line and the source of any script it ran). An excerpt that
    appears there is self-printed, not observed, and is rejected.
    """

    step: int
    command: str
    output: str
    generated_text: str = ""
    # True when the output came from code the agent wrote (python/node/bash
    # scripts or -c snippets). Such output can be shaped by the agent, so it
    # never confirms a pillar on its own.
    agent_authored: bool = False

    @classmethod
    def from_command(cls, step: int, command: str, output: str) -> Optional["Observation"]:
        """Build an observation, or None when the tool cannot yield evidence."""
        try:
            import shlex

            argv = shlex.split(command)
        except ValueError:
            argv = command.split()
        stages = [[]]  # type: List[List[str]]
        for tok in argv:
            if tok == "|":
                stages.append([])
            else:
                stages[-1].append(tok)
        tools = [Path(st[0]).name.lower() for st in stages if st]
        if not tools or tools[0] in NON_EVIDENCE_TOOLS:
            return None
        authored = tools[0].startswith(_INTERPRETERS)
        # Both the raw command and its unescaped argv, so a literal hidden
        # behind shell escaping (\"email\") is still recognised as authored.
        generated = [command, " ".join(argv)]
        for tok in argv:
            if authored and Path(tok).is_file():
                try:
                    generated.append(Path(tok).read_text(errors="replace"))
                except OSError:
                    pass
        return cls(step=step, command=command, output=output,
                   generated_text="\n".join(generated), agent_authored=authored)


@dataclass
class RecordedEvidence:
    """A human-attested artifact (Burp/HAR/raw HTTP/screenshot)."""

    path: str
    sha256: str
    note: str = ""
    attested_at: float = field(default_factory=time.time)
    text: str = ""  # decoded content for text artifacts, "" for binary

    @classmethod
    def attest(cls, path: str, note: str = "") -> "RecordedEvidence":
        p = Path(path).expanduser()
        data = p.read_bytes()
        text = ""
        if b"\x00" not in data[:4096]:
            text = data.decode("utf-8", errors="replace")
        return cls(path=str(p), sha256=hashlib.sha256(data).hexdigest(), note=note, text=text)

    def still_intact(self) -> bool:
        try:
            return hashlib.sha256(Path(self.path).read_bytes()).hexdigest() == self.sha256
        except OSError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "note": self.note,
                "attested_at": self.attested_at, "text_artifact": bool(self.text)}


# ── Claim + result ───────────────────────────────────────────────────────────


@dataclass
class EvidenceRef:
    excerpt: str
    supports: str = "both"      # behavior | impact | both
    step: Optional[int] = None  # optional pointer to the step that produced it

    @classmethod
    def from_any(cls, raw: Any) -> Optional["EvidenceRef"]:
        if isinstance(raw, str):
            return cls(excerpt=raw) if raw.strip() else None
        if isinstance(raw, dict) and str(raw.get("excerpt", "")).strip():
            supports = str(raw.get("supports", "both")).lower()
            if supports not in ("behavior", "impact", "both"):
                supports = "both"
            step = raw.get("step")
            try:
                step = int(step) if step is not None else None
            except (TypeError, ValueError):
                step = None
            return cls(excerpt=str(raw["excerpt"]), supports=supports, step=step)
        return None


@dataclass
class ProofCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class ProofResult:
    verification: Verification
    checks: List[ProofCheck] = field(default_factory=list)
    verified_refs: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def missing(self) -> List[str]:
        return [c.detail for c in self.checks if not c.passed]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification": self.verification.value,
            "checks": [c.to_dict() for c in self.checks],
            "verified_refs": self.verified_refs,
            "missing": self.missing,
        }

    def summary(self) -> str:
        lines = [f"Verification: {self.verification.value.upper()}"]
        for c in self.checks:
            lines.append(f"  [{'✓' if c.passed else '✗'}] {c.name}: {c.detail}")
        return "\n".join(lines)


# ── The gate ─────────────────────────────────────────────────────────────────


class ProofGate:
    """Evaluate a finding claim against verifiable evidence."""

    def evaluate(
        self,
        *,
        title: str,
        behavior: str,
        boundary: str,
        impact: str,
        evidence_refs: Iterable[Any],
        observations: Iterable[Observation],
        recorded: Iterable[RecordedEvidence] = (),
        vuln_class: str = "",
    ) -> ProofResult:
        checks: List[ProofCheck] = []
        observations = list(observations)
        recorded = list(recorded)

        checks.append(self._stated("behavior", behavior,
                                   "describe the observed technical behavior"))
        checks.append(self._stated("boundary", boundary,
                                   "name the security boundary that was crossed"))
        impact_check = self._stated("impact", impact, "state the demonstrated impact")
        if impact_check.passed:
            m = SPECULATIVE_RE.search(impact)
            if m:
                impact_check = ProofCheck(
                    "impact", False,
                    f"impact is speculative ('{m.group(0)}') — state only what was demonstrated",
                )
        checks.append(impact_check)

        refs = [r for r in (EvidenceRef.from_any(x) for x in evidence_refs) if r]
        verified: List[Dict[str, Any]] = []
        rejected: List[str] = []
        for ref in refs:
            hit = self._locate(ref, observations, recorded)
            if hit:
                verified.append(hit)
            else:
                rejected.append(ref.excerpt[:60])

        if not refs:
            checks.append(ProofCheck("evidence", False,
                                     "no evidence excerpts cited from captured output"))
        elif rejected:
            checks.append(ProofCheck(
                "evidence", False,
                f"{len(rejected)} cited excerpt(s) not found in any captured output or "
                f"attested recording: {rejected}",
            ))
        else:
            checks.append(ProofCheck("evidence", True,
                                     f"{len(verified)} excerpt(s) verified against real output"))

        for pillar in ("behavior", "impact"):
            backed = [v for v in verified if v["supports"] in (pillar, "both")]
            independent = [v for v in backed if v["source"] != "agent_script"]
            if not backed:
                ok, detail = False, f"no verified excerpt supports the {pillar}"
            elif not independent:
                ok, detail = False, (
                    f"the {pillar} is backed only by output of agent-written code — "
                    "confirm with a direct tool request or an attested recording"
                )
            else:
                ok, detail = True, f"{len(independent)} verified excerpt(s) support the {pillar}"
            checks.append(ProofCheck(f"{pillar}_evidence", ok, detail))

        cls = detect_class(title, vuln_class)
        if cls in REQUIRES_RECORDED_PROOF:
            intact = [r for r in recorded if r.still_intact()]
            checks.append(ProofCheck(
                "recorded_proof", bool(intact),
                f"{len(intact)} attested recording(s) present" if intact
                else f"{cls}: {REQUIRES_RECORDED_PROOF[cls]}",
            ))

        for r in recorded:
            if not r.still_intact():
                checks.append(ProofCheck(
                    "recording_integrity", False,
                    f"attested file changed or missing since attestation: {r.path}",
                ))

        status = (Verification.CONFIRMED if all(c.passed for c in checks)
                  else Verification.LEAD)
        return ProofResult(status, checks, verified)

    @staticmethod
    def _stated(name: str, value: str, hint: str) -> ProofCheck:
        if len(_norm(value)) < 10:
            return ProofCheck(name, False, f"missing — {hint}")
        return ProofCheck(name, True, "stated")

    @staticmethod
    def _locate(
        ref: EvidenceRef,
        observations: List[Observation],
        recorded: List[RecordedEvidence],
    ) -> Optional[Dict[str, Any]]:
        needle = _norm(ref.excerpt)
        if len(needle) < MIN_EXCERPT_LEN:
            return None
        # Prefer independent tool output over agent-written code, then the
        # step the excerpt was attributed to.
        ordered = sorted(
            observations,
            key=lambda o: (o.agent_authored, ref.step is not None and o.step != ref.step),
        )
        for obs in ordered:
            if needle in _norm(obs.output) and needle not in _norm(obs.generated_text):
                return {"excerpt": ref.excerpt, "supports": ref.supports,
                        "source": "agent_script" if obs.agent_authored else "observed",
                        "step": obs.step, "command": obs.command}
        for rec in recorded:
            if rec.text and rec.still_intact() and needle in _norm(rec.text):
                return {"excerpt": ref.excerpt, "supports": ref.supports,
                        "source": "recorded", "path": rec.path, "sha256": rec.sha256}
        return None
