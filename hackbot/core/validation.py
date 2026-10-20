"""
HackBot Pre-Validation (7-Question Gate bridge)
===============================================
Applies the *mechanically checkable* part of the hunter's own validation
material to a HackBot finding, and prepares the rest for the Claude Code
agents/skills that already implement it:

* ``~/.claude/agents/validator.md``  — 7-Question Gate, never-submit list,
  conditionally-valid chain table (read at runtime, not copied).
* YesWeHack ``gotchas`` skill (``ywh:gotchas``) — per-class minimum proof,
  common N/A, overclaim traps (read at runtime and attached to the verdict
  as the manual checklist for the claimed class).

What HackBot can decide offline from its own data:

* Q1 real request  — proof gate CONFIRMED with observed/recorded evidence.
* Q3 in scope      — the finding's asset against the enforced ScopePolicy.
* Q4 privileges    — ``privileges_required`` of the finding.
* Q6 real impact   — proof gate impact pillar + class auto-checks
  (cross-identity proof for IDOR/BOLA/auth classes, SQL error-only, CORS
  without credentials, DNS-only SSRF).
* Q7 never-submit  — the hunter's never-submit list + chain table.

What it cannot decide (always handed to the human / ``validator`` agent):
Q2 program-accepted impact (unless a program rules file lists exclusions),
Q5 known/duplicate behavior, Gate 2 dedup search, Gate 3 report quality.

Consequently HackBot never emits PASS. Its best verdict is
``READY_FOR_VALIDATOR``; the final PASS belongs to the validator agent and
``ywh:triage``.
"""

from __future__ import annotations

import glob
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

VALIDATOR_PATH = Path("~/.claude/agents/validator.md").expanduser()
GOTCHAS_GLOBS = [
    "~/.claude/plugins/marketplaces/yeswehack/skills/gotchas/SKILL.md",
    "~/.claude/plugins/cache/yeswehack/ywh/*/skills/gotchas/SKILL.md",
]


class Verdict(str, Enum):
    READY_FOR_VALIDATOR = "ready_for_validator"  # all offline checks passed
    REVIEW_REQUIRED = "review_required"          # FP signals need a human decision first
    KILL = "kill"
    DOWNGRADE = "downgrade"
    CHAIN_REQUIRED = "chain_required"


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

# ── Never-submit matchers ────────────────────────────────────────────────────
# Each matcher is active only when its hint appears in the hunter's loaded
# never-submit list, so the list file stays the source of truth.
# (hint in list, regex over title/class/description, "unless" regex over the
#  same text + verified excerpts — the qualifier that makes it submittable)
_NEVER_SUBMIT_MATCHERS: List[Tuple[str, str, str]] = [
    ("missing headers",
     r"missing (security )?headers?|\b(csp|hsts|x-frame-options)\b (header )?(is )?missing", ""),
    ("spf", r"\b(spf|dkim|dmarc)\b", ""),
    ("introspection", r"graphql introspection|introspection (is )?enabled",
     r"\b(idor|bola|auth(entication|orization)? bypass|mutation)\b"),
    ("banner", r"\b(banner|version) disclosure|server version (header|banner)",
     r"\bcve-\d{4}-\d+\b.*(exploit|confirmed)"),
    ("clickjacking", r"clickjacking|ui redress", r"\brecorded_proof_ok\b"),
    ("tabnabbing", r"tabnabbing", ""),
    ("csv injection", r"csv injection|formula injection", r"code execution|\bcalc\.exe\b"),
    ("cors wildcard", r"\bcors\b", r"access-control-allow-credentials:\s*true"),
    ("logout csrf", r"logout csrf|csrf (on|in) logout", ""),
    ("self-xss", r"self[- ]xss", ""),
    ("open redirect", r"open redirect",
     r"\b(oauth|token|code=|redirect_uri)\b.*\b(stolen|leak|captured)"),
    ("client_secret", r"client[_ ]secret", ""),
    # Only SSRF claims resting on DNS / out-of-band callbacks; a full HTTP read is a
    # different (reportable) finding, judged by Q6.
    ("ssrf dns", r"ssrf\b.*\b(dns|callback|interaction|pingback|out-of-band|oob)\b|"
                 r"\b(dns|oob)\b.*\bssrf",
     r"http/1\.[01] \d{3}|\binstance-id\b|\bami-id\b|<html|\{\s*\""),
    ("host header", r"host header injection", r"password reset|poison(ed|ing)"),
    ("rate limit", r"\brate[- ]limit",
     r"\b(otp|2fa|mfa|password reset|coupon|gift|voucher|redeem|transfer)\b"),
    # Logout only: a session surviving a *password change* or role downgrade is
    # a different, usually accepted, finding.
    ("not invalidated",
     r"(not invalidated|still valid|remains valid|still accepted)\W+(\w+\W+){0,4}"
     r"(on|after) logout|logout\W+(\w+\W+){0,4}(not invalidated|still valid)", ""),
    ("concurrent sessions", r"concurrent sessions?", ""),
    ("internal ip", r"internal ip", ""),
    ("cookie flags", r"cookie (flag|attribute)s?|missing (httponly|secure) flag", ""),
]

_BUILTIN_NEVER_SUBMIT = [
    "Missing headers (CSP/HSTS/X-Frame-Options)", "Missing SPF/DKIM/DMARC",
    "GraphQL introspection alone", "Banner/version disclosure without CVE exploit",
    "Clickjacking without sensitive action PoC", "Self-XSS", "Open redirect alone",
    "SSRF DNS-only", "CORS wildcard without credentialed exfil PoC", "Logout CSRF",
    "Missing cookie flags alone",
]

AUTH_CLASSES = ("idor", "bola", "auth bypass", "authentication bypass", "authorization",
                "account takeover", "ato", "privilege escalation", "privesc", "bfla")

# finding class → gotchas section title (lowercase)
_GOTCHAS_ALIASES = {
    "xss": "xss", "sqli": "sqli", "sql injection": "sqli", "ssrf": "ssrf",
    "idor": "idor / bola", "bola": "idor / bola", "csrf": "csrf", "rce": "rce",
    "command injection": "rce", "ssti": "ssti", "xxe": "xxe",
    "open redirect": "open redirect", "auth bypass": "auth bypass",
    "authentication bypass": "auth bypass", "information disclosure":
    "information disclosure / secret leak", "secret leak": "information disclosure / secret leak",
    "race condition": "race condition", "cors": "cors misconfiguration",
    "path traversal": "path traversal / lfi", "lfi": "path traversal / lfi",
}

_VERTICAL_WORDS = ("privilege escalation", "privesc", "mass assignment", "mass_assignment",
                   "bopla", "role", "vertical")
_ELEVATED_RE = re.compile(r"\"(role|roles|isAdmin|is_admin|is_staff|admin|permissions?|scope|"
                          r"groups?)\"\s*:\s*\"?(admin|administrator|root|superuser|staff|true|"
                          r"owner|manager|write|\*)", re.I)

_SQL_ERROR_RE = re.compile(
    r"sql syntax|mysql_fetch|ora-\d{5}|pg::|sqlstate|sqlite3?\.|unclosed quotation|"
    r"odbc|syntax error at or near|warning: mysql", re.I)
_DNS_ONLY_RE = re.compile(r"\bdns\b.*(interaction|query|lookup|callback)", re.I)


# ── Rule loading ─────────────────────────────────────────────────────────────


@dataclass
class RuleSet:
    never_submit: List[str] = field(default_factory=list)
    chains: List[Tuple[str, str]] = field(default_factory=list)  # (have, chain needed)
    gotchas: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    sources: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, validator_path: Optional[Path] = None,
             gotchas_path: Optional[Path] = None) -> "RuleSet":
        rules = cls()
        vpath = Path(validator_path) if validator_path else VALIDATOR_PATH
        if vpath.is_file():
            text = vpath.read_text(errors="replace")
            rules.never_submit = _code_block_lines(text, "Never-Submit List")
            for line in _code_block_lines(text, "Conditionally Valid"):
                parts = [p.strip(" +") for p in line.split("→")]
                if len(parts) >= 2:
                    rules.chains.append((parts[0], parts[1]))
            rules.sources["validator"] = str(vpath)
        if not rules.never_submit:
            rules.never_submit = list(_BUILTIN_NEVER_SUBMIT)
            rules.sources.setdefault("validator", "built-in fallback (validator.md not found)")

        gpath = Path(gotchas_path) if gotchas_path else _find_gotchas()
        if gpath and gpath.is_file():
            rules.gotchas = _parse_gotchas(gpath.read_text(errors="replace"))
            rules.sources["gotchas"] = str(gpath)
        else:
            rules.sources["gotchas"] = "not found (ywh gotchas skill not installed)"
        return rules

    def active_never_submit(self) -> List[Tuple[re.Pattern, Optional[re.Pattern], str]]:
        """(matcher, unless, list entry) for every matcher present in the list."""
        out = []
        for hint, pattern, unless in _NEVER_SUBMIT_MATCHERS:
            for entry in self.never_submit:
                if hint in entry.lower():
                    out.append((re.compile(pattern, re.I),
                                re.compile(unless, re.I | re.S) if unless else None, entry))
                    break
        return out

    def chain_for(self, entry: str) -> Optional[str]:
        low = entry.lower()
        for have, need in self.chains:
            key = have.lower().split()[0:2]
            if " ".join(key) in low:
                return f"{have} → {need}"
        return None

    def gotchas_for(self, vuln_class: str) -> Dict[str, List[str]]:
        section = _GOTCHAS_ALIASES.get(vuln_class.lower().strip(), vuln_class.lower().strip())
        return self.gotchas.get(section, {})


def _find_gotchas() -> Optional[Path]:
    for pattern in GOTCHAS_GLOBS:
        hits = sorted(glob.glob(str(Path(pattern).expanduser())))
        if hits:
            return Path(hits[-1])
    return None


def _code_block_lines(markdown: str, heading: str) -> List[str]:
    m = re.search(rf"^##\s+{re.escape(heading)}.*?```\w*\n(.*?)```", markdown, re.S | re.M)
    if not m:
        return []
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]


def _parse_gotchas(markdown: str) -> Dict[str, Dict[str, List[str]]]:
    out: Dict[str, Dict[str, List[str]]] = {}
    for sec in re.split(r"^## ", markdown, flags=re.M)[1:]:
        title, _, body = sec.partition("\n")
        name = title.strip().lower()
        parts: Dict[str, List[str]] = {}
        current = None
        for line in body.splitlines():
            head = re.match(r"^\*\*(.+?)\*\*", line.strip())
            if head:
                label = head.group(1).lower()
                current = ("minimum_proof" if "minimum" in label else
                           "common_na" if "n/a" in label else
                           "overclaim" if "overclaim" in label else "other")
                parts.setdefault(current, [])
                continue
            if current and line.startswith("- "):
                parts[current].append(line[2:].strip())
            elif current and line.startswith("  ") and parts[current]:
                parts[current][-1] += " " + line.strip()
        if parts:
            out[name] = parts
    return out


# ── Program rules (optional, from the scope file) ────────────────────────────


@dataclass
class ProgramRules:
    """Optional program rules: ``excluded_classes`` and ``severity_caps``.

    Read from the same YAML file as the scope (extra keys are ignored by
    the scope parser), e.g.::

        in_scope: ["*.acme.com"]
        excluded_classes: [self-xss, clickjacking, rate limit]
        severity_caps: {open redirect: Low}
    """

    excluded_classes: List[str] = field(default_factory=list)
    severity_caps: Dict[str, str] = field(default_factory=dict)
    source: str = ""

    @classmethod
    def from_file(cls, path: str) -> Optional["ProgramRules"]:
        try:
            data = yaml.safe_load(Path(path).expanduser().read_text())
        except (OSError, yaml.YAMLError):
            return None
        if not isinstance(data, dict):
            return None
        if "excluded_classes" not in data and "severity_caps" not in data:
            return None
        return cls(
            excluded_classes=[str(x).lower() for x in data.get("excluded_classes") or []],
            severity_caps={str(k).lower(): str(v).capitalize()
                           for k, v in (data.get("severity_caps") or {}).items()},
            source=str(path),
        )


# ── Result ───────────────────────────────────────────────────────────────────


@dataclass
class QuestionResult:
    q: str
    status: str  # pass | fail | partial | human
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"q": self.q, "status": self.status, "detail": self.detail}


@dataclass
class ValidationResult:
    verdict: Verdict
    reason: str
    action: str
    questions: List[QuestionResult] = field(default_factory=list)
    human_checks: List[str] = field(default_factory=list)
    gotchas: Dict[str, List[str]] = field(default_factory=dict)
    suggested_severity: str = ""
    sources: Dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        failed = next((q.q for q in self.questions if q.status in ("fail", "partial")), "")
        if self.verdict == Verdict.KILL and failed:
            return f"KILL {failed}"
        return self.verdict.value.upper()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value, "label": self.label, "reason": self.reason,
            "action": self.action, "questions": [q.to_dict() for q in self.questions],
            "human_checks": self.human_checks, "gotchas": self.gotchas,
            "suggested_severity": self.suggested_severity, "sources": self.sources,
        }


# ── Validator ────────────────────────────────────────────────────────────────


def _lower_severity(sev: str) -> str:
    try:
        i = SEVERITY_ORDER.index(sev.capitalize())
    except ValueError:
        return "Low"
    return SEVERITY_ORDER[max(0, i - 1)]


# Impact claims that need their own evidence (claim regex, evidence regex | None).
# None = never provable inside a lab run, so the claim must not be made.
_OVERCLAIMS = [
    (r"cloud metadata|metadata service|instance metadata|iam credentials?",
     r"169\.254\.169\.254|meta-?data|instance-id|security-credentials"),
    (r"internal (network|services?|hosts?|systems?)|\bpivot",
     r"\b10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\.internal\b|"
     r"\.local\b|localhost|127\.0\.0\.1"),
    (r"credential[- ]stuffing|on other (services|sites)", None),
    (r"full (data(base)? )?compromise|complete compromise|entire database|full database|"
     r"all (user )?data\b|full server compromise", None),
    (r"remote code execution|\brce\b|arbitrary code execution",
     r"uid=\d+|gid=\d+|root:x:0|nt authority"),
]
_RCE_CLASSES = ("rce", "command injection", "code injection", "deserialization", "ssti")


def _impact_overclaim(impact: str, excerpts: str, text: str) -> str:
    low = impact.lower()
    for claim, needs in _OVERCLAIMS:
        m = re.search(claim, low)
        if not m:
            continue
        if "rce" in claim and any(c in text for c in _RCE_CLASSES) and needs and \
                re.search(needs, excerpts, re.I):
            continue
        if needs and re.search(needs, excerpts, re.I):
            continue
        return m.group(0)
    return ""


class FindingValidator:
    def __init__(self, rules: Optional[RuleSet] = None):
        self.rules = rules or RuleSet.load()

    def validate(
        self,
        finding: Dict[str, Any],
        scope_policy: Any = None,
        program: Optional[ProgramRules] = None,
        confirmed_titles: Iterable[str] = (),
    ) -> ValidationResult:
        title = str(finding.get("raw_title") or finding.get("title", ""))
        vclass = str(finding.get("vuln_class", "")).lower()
        text = f"{title} {vclass} {finding.get('description', '')}"
        proof = finding.get("proof") or {}
        refs = proof.get("verified_refs") or []
        excerpts = " ".join(r.get("excerpt", "") for r in refs)
        severity = str(finding.get("severity", "Info"))
        q: List[QuestionResult] = []

        # Q1 — real request / recorded evidence
        independent = [r for r in refs if r.get("source") in ("observed", "recorded")]
        if finding.get("verification") == "confirmed" and independent:
            q.append(QuestionResult(
                "Q1", "pass",
                f"proof gate confirmed with {len(independent)} verified excerpt(s)",
            ))
        else:
            q.append(QuestionResult("Q1", "fail",
                                    "no confirmed PoC — proof gate verdict is LEAD"))

        # Q2 — impact accepted by the program
        excluded = next((c for c in (program.excluded_classes if program else [])
                         if c and c in text.lower()), None)
        if excluded:
            q.append(QuestionResult("Q2", "fail", f"program excludes '{excluded}'"))
        elif program:
            q.append(QuestionResult("Q2", "pass",
                                    f"class not in program exclusions ({program.source})"))
        else:
            q.append(QuestionResult("Q2", "human",
                                    "no program rules file — check accepted impact types"))

        # Q3 — asset in scope (the declared asset and every evidence command)
        asset = str(finding.get("asset", "")).strip()
        url_in_asset = re.search(r"https?://[^\s'\"<>]+", asset)
        if url_in_asset:
            asset = url_in_asset.group(0).rstrip(".,;)")
        commands = [r["command"] for r in refs if r.get("command")]
        if scope_policy is None:
            q.append(QuestionResult("Q3", "human", "no enforced scope policy"))
        elif not asset and not commands:
            q.append(QuestionResult("Q3", "human", "finding has no asset or evidence command"))
        else:
            bad = []
            if asset and not scope_policy.check_raw_target(asset)[0]:
                bad.append(asset)
            for cmd in commands:
                if scope_policy.check_command(cmd).verdict.value == "deny":
                    bad.append(cmd)
            q.append(QuestionResult(
                "Q3", "fail" if bad else "pass",
                f"out of scope: {bad}" if bad else "asset and evidence in scope",
            ))

        # Q4 — privileged access
        priv = str(finding.get("privileges_required", "")).lower()
        if priv in ("admin", "high", "administrator", "root"):
            q.append(QuestionResult("Q4", "fail", "requires admin/privileged access"))
        elif priv in ("none", "user", "low", "unauthenticated", "anonymous"):
            q.append(QuestionResult("Q4", "pass", f"privileges required: {priv}"))
        else:
            q.append(QuestionResult("Q4", "human", "privileges_required not stated"))

        # Q5 — known / documented behavior: never decidable offline
        q.append(QuestionResult("Q5", "human",
                                "search disclosed reports, changelog and docs (Gate 2)"))

        # Q6 — impact beyond "technically possible"
        q.append(self._q6(finding, vclass, text, excerpts, proof))

        # Q7 — never-submit list
        recorded_ok = any(c.get("name") == "recorded_proof" and c.get("passed")
                          for c in proof.get("checks", []))
        qualifier = f"{text} {excerpts} {'recorded_proof_ok' if recorded_ok else ''}"
        q.append(self._q7(finding, text, qualifier, set(t.lower() for t in confirmed_titles)))

        gotchas = self.rules.gotchas_for(vclass or self._guess_class(text))
        human = [x.detail for x in q if x.status == "human"]
        human += ["Gate 2: dedup search (disclosed reports, GitHub issues)",
                  "Gate 3: report quality (title formula, exact request, CVSS, fix)"]
        label = vclass or "class"
        human += [f"[{label} minimum proof] {m}" for m in gotchas.get("minimum_proof", [])]

        result = self._decide(q, severity, program, text)
        fp = finding.get("fp_triage") or {}
        review = (fp.get("review") or {}).get("decision")
        if review == "false_positive":
            result = ValidationResult(Verdict.KILL, "dismissed as false positive by the hunter",
                                      "Kept for the record; not reportable.")
        elif result.verdict == Verdict.READY_FOR_VALIDATOR and \
                fp.get("label") == "likely_false_positive" and review != "valid":
            codes = ", ".join(x["code"] for x in fp.get("signals", []))
            result = ValidationResult(
                Verdict.REVIEW_REQUIRED, f"false-positive signals not reviewed: {codes}",
                "Inspect the evidence, then /review <n> valid|false_positive|needs_more_evidence.",
            )
        result.questions = q
        result.human_checks = human
        result.gotchas = gotchas
        result.sources = dict(self.rules.sources)
        if program:
            result.sources["program"] = program.source
        return result

    # ── per-question helpers ─────────────────────────────────────────────
    def _q6(self, finding, vclass, text, excerpts, proof) -> QuestionResult:
        checks = {c.get("name"): c.get("passed") for c in proof.get("checks", [])}
        if not checks.get("impact") or not checks.get("impact_evidence"):
            return QuestionResult("Q6", "fail", "impact not demonstrated by verified evidence")

        low = text.lower()
        if finding.get("boundary_type") == "tenant_isolation":
            at, vt = str(finding.get("attacker_tenant", "")), str(finding.get("victim_tenant", ""))
            if not at or not vt or at == vt:
                return QuestionResult(
                    "Q6", "fail",
                    "tenant isolation claimed but attacker and victim are not in two "
                    "distinct tenants in the identity vault")
        a = str(finding.get("attacker_identity", "")).strip()
        b = str(finding.get("victim_identity", "")).strip()
        vertical = not b and any(w in low for w in _VERTICAL_WORDS)
        if vertical:
            # Escalating the attacker's OWN account (e.g. role set at sign-up): there is
            # no victim; the evidence must show the elevated privilege itself.
            if not _ELEVATED_RE.search(excerpts):
                return QuestionResult(
                    "Q6", "fail",
                    "vertical privilege escalation: evidence must show the elevated "
                    "role/permission")
        elif any(c in low for c in AUTH_CLASSES):
            vid = str(finding.get("victim_identifier", "")).strip()
            if not a or not b or a == b:
                return QuestionResult(
                    "Q6", "fail", "auth-class finding needs two distinct identities (A reads B)",
                )
            markers = [m for m in (finding.get("victim_markers") or []) if m]
            candidates = [c for c in [vid] + markers if c]
            if not any(c in excerpts for c in candidates):
                return QuestionResult("Q6", "fail",
                                      "victim B's identifier must appear in verified evidence")
        if ("sqli" in low or "sql injection" in low) and excerpts and \
                _SQL_ERROR_RE.search(excerpts) and not re.search(
                    r"version|sleep|banner|current_user|database\(\)|sentinel|\d+\.\d+\.\d+",
                    excerpts, re.I):
            return QuestionResult("Q6", "partial", "SQL error only — no data/time/boolean oracle")
        if "ssrf" in low and _DNS_ONLY_RE.search(excerpts) and "http" not in excerpts.lower():
            return QuestionResult("Q6", "partial", "DNS callback only — no HTTP reach or data")
        if "cors" in low and "access-control-allow-credentials: true" not in excerpts.lower():
            return QuestionResult("Q6", "fail",
                                  "CORS without Access-Control-Allow-Credentials: true in evidence")
        overclaim = _impact_overclaim(str(finding.get("impact", "")), excerpts, low)
        if overclaim:
            return QuestionResult(
                "Q6", "partial",
                f"impact claims {overclaim!r}, which the verified evidence does not show — "
                "state only what the excerpts prove")
        return QuestionResult("Q6", "pass", "impact backed by verified evidence")

    def _q7(self, finding, text, qualifier, confirmed) -> QuestionResult:
        chained = [str(c).lower() for c in finding.get("chained_with") or []]
        for matcher, unless, entry in self.rules.active_never_submit():
            if not matcher.search(text):
                continue
            if unless is not None and unless.search(qualifier):
                continue  # the qualifying proof is present (e.g. ACAC: true)
            proven_chain = [c for c in chained if c in confirmed]
            if proven_chain:
                return QuestionResult("Q7", "pass",
                                      f"'{entry}' but chained with confirmed {proven_chain}")
            chain = self.rules.chain_for(entry)
            if chain:
                return QuestionResult("Q7", "chain", f"'{entry}' — chain required: {chain}")
            return QuestionResult("Q7", "fail", f"on never-submit list: '{entry}'")
        return QuestionResult("Q7", "pass", "not on the never-submit list")

    @staticmethod
    def _guess_class(text: str) -> str:
        low = text.lower()
        for alias in _GOTCHAS_ALIASES:
            if alias in low:
                return alias
        return ""

    @staticmethod
    def _decide(q: List[QuestionResult], severity: str, program, text) -> ValidationResult:
        for item in q:
            if item.status == "fail":
                return ValidationResult(
                    Verdict.KILL, f"{item.q} fails: {item.detail}",
                    "Do not write a report. Keep it as a lead or move on.",
                )
            if item.status == "partial":
                return ValidationResult(
                    Verdict.DOWNGRADE, f"{item.q}: {item.detail}",
                    "Prove the full impact, or report at the lower severity.",
                    suggested_severity=_lower_severity(severity),
                )
            if item.status == "chain":
                return ValidationResult(
                    Verdict.CHAIN_REQUIRED, item.detail,
                    "Build and confirm the chain end-to-end, then report both together.",
                )
        cap = None
        if program:
            cap = next((v for k, v in program.severity_caps.items() if k in text.lower()), None)
        if cap and SEVERITY_ORDER.index(cap) < SEVERITY_ORDER.index(severity.capitalize()):
            return ValidationResult(
                Verdict.DOWNGRADE, f"program caps this class at {cap}",
                f"Report at {cap}.", suggested_severity=cap,
            )
        return ValidationResult(
            Verdict.READY_FOR_VALIDATOR,
            "all offline checks passed — remaining questions need the validator agent/human",
            "Export the handoff packet and run /hackbot-validate in Claude Code.",
        )
