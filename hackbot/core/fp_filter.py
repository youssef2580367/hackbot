"""
HackBot False-Positive Classifier
=================================
Flags findings whose evidence matches a well-known false-positive pattern,
with a plain explanation for each signal. It never deletes, hides or
downgrades anything by itself:

* the machine assigns a **label** — ``no_fp_signal``, ``needs_review`` or
  ``likely_false_positive`` — plus the signals that produced it;
* only a **human review** (``valid`` / ``false_positive`` /
  ``needs_more_evidence``) changes how a finding is reported, and that
  decision is kept with its note and timestamp (and mirrored to the
  vulnerability DB's remediation log).

Signals are evaluated on the finding text plus the *full captured output*
of every step its evidence cites, not only the short excerpts.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class FPLabel(str, Enum):
    NO_SIGNAL = "no_fp_signal"
    NEEDS_REVIEW = "needs_review"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class ReviewDecision(str, Enum):
    VALID = "valid"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


@dataclass
class FPSignal:
    code: str
    confidence: str  # high | medium
    explanation: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "confidence": self.confidence,
                "explanation": self.explanation}


@dataclass
class Context:
    title: str
    vclass: str
    text: str            # title + class + description + pillars, lowercased
    excerpts: str        # verified excerpts
    outputs: str         # full output of cited steps
    commands: List[str]
    finding: Dict[str, Any]
    step_outputs: List[str] = field(default_factory=list)  # one entry per cited step


_WAF_RE = re.compile(
    r"attention required!? \| cloudflare|cf-ray:|access denied.{0,80}(akamai|reference #)|"
    r"request (was )?blocked|incapsula incident|mod_security|web application firewall|"
    r"sucuri website firewall|captcha|<title>\s*(403 forbidden|access denied)", re.I | re.S)
_SOFT_404_RE = re.compile(r"\b(page|file|resource) (was )?not found\b|\b404\b.{0,40}not found|"
                          r"doesn'?t exist|no such (page|file)", re.I)
_LOGIN_RE = re.compile(r"(location:\s*\S*(login|signin|sign-in|auth)\b)|"
                       r"<input[^>]+type=[\"']?password", re.I)
_SPA_SHELL_RE = re.compile(r"<div id=[\"'](root|app|__next)[\"']>\s*</div>|ng-version=|"
                           r"<noscript>you need to enable javascript", re.I)
_DEFAULT_PAGE_RE = re.compile(r"welcome to nginx|apache2 (ubuntu|debian) default page|"
                              r"it works!|iis windows server|test page for the apache", re.I)
_ENCODED_PAYLOAD_RE = re.compile(r"&lt;\s*(script|img|svg|iframe)|\\u003c(script|img|svg)|"
                                 r"%3c(script|img|svg)", re.I)
_RAW_PAYLOAD_RE = re.compile(r"<\s*(script|img|svg|iframe)[\s>/]", re.I)
_PUBLISHABLE_KEY_RE = re.compile(
    r"\bpk_(live|test)_[0-9a-z]{10,}|\bsk_test_[0-9a-z]{10,}|\bAIza[0-9A-Za-z_\-]{35}\b|"
    r"https://[0-9a-f]{32}@[\w.-]*sentry\.io|\b6L[0-9A-Za-z_\-]{38}\b|\bpk\.eyJ[0-9A-Za-z_\-.]+",
    re.I)
_SCANNER_TOOLS = ("nuclei", "nikto", "wpscan", "whatweb", "joomscan", "wapiti", "zap",
                  "nmap", "sslscan", "testssl")
_AUTH_WORDS = ("idor", "bola", "bfla", "auth bypass", "authentication bypass",
               "authorization bypass", "account takeover", "privilege escalation")


def _has(text: str, words) -> bool:
    return any(w in text for w in words)


# ── Rules: (code, applies(ctx) -> Optional[FPSignal]) ───────────────────────


def _waf(ctx: Context) -> Optional[FPSignal]:
    if _WAF_RE.search(ctx.outputs) or _WAF_RE.search(ctx.excerpts):
        return FPSignal("WAF_BLOCK_PAGE", "high",
                        "cited response looks like a WAF/CDN block or challenge page — the "
                        "application itself may never have processed the payload")
    return None


def _soft_404(ctx: Context) -> Optional[FPSignal]:
    if not _has(ctx.text, ("disclosure", "exposed", "exposure", "backup", "traversal",
                           "lfi", "directory listing", "sensitive file")):
        return None
    # D12: judge each cited step on its own — a control step's real 404 must not make
    # the positive steps look like soft 404s.
    ok_steps = [o for o in (ctx.step_outputs or [ctx.outputs])
                if re.search(r"http/[\d.]+ 200", o, re.I)]
    if ok_steps and all(_SOFT_404_RE.search(o) for o in ok_steps):
        return FPSignal("SOFT_404", "high",
                        "status 200 but the body is a 'not found' page — a soft 404, not "
                        "exposed content")
    return None


def _login_redirect(ctx: Context) -> Optional[FPSignal]:
    if _has(ctx.text, _AUTH_WORDS) and _LOGIN_RE.search(ctx.outputs):
        return FPSignal("LOGIN_REDIRECT", "high",
                        "the response redirects to / renders a login form — access was not "
                        "actually granted")
    return None


def _spa_shell(ctx: Context) -> Optional[FPSignal]:
    if _has(ctx.text, _AUTH_WORDS + ("admin panel", "admin page", "/admin")) and \
            _SPA_SHELL_RE.search(ctx.outputs) and not re.search(r"[\[{]\s*\"", ctx.excerpts):
        return FPSignal("SPA_SHELL_ONLY", "high",
                        "evidence is the client-side app shell; the framework serves it to "
                        "everyone — show protected API data or a privileged action instead")
    return None


def _default_page(ctx: Context) -> Optional[FPSignal]:
    if _DEFAULT_PAGE_RE.search(ctx.outputs) or _DEFAULT_PAGE_RE.search(ctx.excerpts):
        return FPSignal("DEFAULT_PAGE", "medium",
                        "a stock web-server default page is not a vulnerability by itself")
    return None


def _encoded_xss(ctx: Context) -> Optional[FPSignal]:
    if "xss" not in ctx.text and "cross-site scripting" not in ctx.text:
        return None
    if _ENCODED_PAYLOAD_RE.search(ctx.excerpts) and not _RAW_PAYLOAD_RE.search(ctx.excerpts):
        return FPSignal("ENCODED_REFLECTION", "high",
                        "the payload is reflected HTML/URL-encoded — the browser renders it "
                        "as text, so it does not execute")
    return None


def _publishable_key(ctx: Context) -> Optional[FPSignal]:
    if not _has(ctx.text, ("key", "secret", "token", "credential", "disclosure", "leak")):
        return None
    if _PUBLISHABLE_KEY_RE.search(ctx.excerpts) and not re.search(
            r"\b(sk_live_|akia|ghp_|xox[bp]-|-----begin)", ctx.excerpts, re.I):
        return FPSignal("PUBLISHABLE_KEY", "high",
                        "the 'secret' matches a key designed to ship client-side (Stripe pk_, "
                        "Google browser key, Sentry DSN, reCAPTCHA site key, Mapbox public "
                        "token) — prove a non-intended capability or drop it")
    return None


def _scanner_only(ctx: Context) -> Optional[FPSignal]:
    if not ctx.commands:
        return None
    tools = {c.strip().split()[0].rsplit("/", 1)[-1].lower() for c in ctx.commands if c.strip()}
    if tools and tools <= set(_SCANNER_TOOLS):
        return FPSignal("SCANNER_ONLY", "medium",
                        f"evidence comes only from scanner output ({', '.join(sorted(tools))}) "
                        "— reproduce it with a direct request before trusting it")
    return None


def _self_target(ctx: Context) -> Optional[FPSignal]:
    if not _has(ctx.text, _AUTH_WORDS):
        return None
    a = str(ctx.finding.get("attacker_identity", "")).strip().lower()
    b = str(ctx.finding.get("victim_identity", "")).strip().lower()
    if a and b and a == b:
        return FPSignal("SELF_TARGET", "high",
                        "attacker and victim are the same account — reading your own data is "
                        "not an authorization bug")
    return None


def _status_only(ctx: Context) -> Optional[FPSignal]:
    ex = ctx.excerpts.strip().lower()
    if ex and re.fullmatch(r"(http/[\d.]+ )?\d{3}( [a-z ]+)?", ex):
        return FPSignal("STATUS_CODE_ONLY", "medium",
                        "the only evidence is a status line — a 200 is not proof of data access "
                        "or impact")
    return None


_ERROR_CLAIM_RE = re.compile(r"traceback|stack ?trace|verbose error|error (message|page|"
                             r"disclosure)|debug (info|output)|exception (details|message)",
                             re.I)
_TRACE_RE = re.compile(r"traceback \(most recent call last\)|\bat [\w.$]+\(|"
                       r"\bfile \"[^\"]+\", line \d+|exception in thread|stack trace", re.I)
_SECRET_RE = re.compile(r"passw(or)?d\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|token\s*[=:]|"
                        r"-----begin [a-z ]*private key|(postgres|mysql|mongodb)(\+\w+)?://\S+:\S+@|"
                        r"aws_secret|akia[0-9a-z]{16}", re.I)


_OTHER_CLASS_RE = re.compile(r"injection|sqli|traversal|ssrf|idor|bola|bfla|bypass|"
                             r"\brce\b|command|xss|xxe|deserializ|takeover|escalation", re.I)


def _verbose_error_only(ctx: Context) -> Optional[FPSignal]:
    """D16: a finding whose whole case is an error message / stack trace."""
    if not _ERROR_CLAIM_RE.search(ctx.text) or _OTHER_CLASS_RE.search(ctx.text):
        return None
    evidence = f"{ctx.excerpts}\n{ctx.outputs}"
    if not _TRACE_RE.search(evidence) or _SECRET_RE.search(evidence):
        return None
    return FPSignal("VERBOSE_ERROR_ONLY", "high",
                    "the evidence is an error message / stack trace without secrets or a "
                    "security effect — expected behaviour or informational unless it is "
                    "chained into a real impact")


RULES: List[Callable[[Context], Optional[FPSignal]]] = [
    _waf, _soft_404, _login_redirect, _spa_shell, _default_page, _encoded_xss,
    _publishable_key, _scanner_only, _self_target, _status_only, _verbose_error_only,
]


@dataclass
class FPReview:
    decision: ReviewDecision
    note: str = ""
    reviewer: str = "hunter"
    at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"decision": self.decision.value, "note": self.note,
                "reviewer": self.reviewer, "at": self.at}


class FalsePositiveClassifier:
    def classify(
        self, finding: Dict[str, Any], cited_outputs: Dict[int, Dict[str, str]],
    ) -> Dict[str, Any]:
        proof = finding.get("proof") or {}
        refs = proof.get("verified_refs") or []
        raw_refs = finding.get("evidence_refs") or []
        excerpts = " ".join(r.get("excerpt", "") for r in refs) or " ".join(
            (r.get("excerpt", "") if isinstance(r, dict) else str(r)) for r in raw_refs)
        steps = {r.get("step") for r in refs if r.get("step") is not None}
        outputs = "\n".join(cited_outputs[s]["output"] for s in steps if s in cited_outputs)
        commands = [cited_outputs[s]["command"] for s in steps if s in cited_outputs]
        text = " ".join(str(finding.get(k, "")) for k in (
            "raw_title", "title", "vuln_class", "description", "behavior", "impact")).lower()
        ctx = Context(str(finding.get("raw_title", "")), str(finding.get("vuln_class", "")),
                      text, excerpts, outputs, commands, finding,
                      [cited_outputs[s]["output"] for s in sorted(steps) if s in cited_outputs])

        signals = [s for s in (rule(ctx) for rule in RULES) if s]
        if any(s.confidence == "high" for s in signals):
            label = FPLabel.LIKELY_FALSE_POSITIVE
        elif signals:
            label = FPLabel.NEEDS_REVIEW
        else:
            label = FPLabel.NO_SIGNAL
        return {"label": label.value, "signals": [s.to_dict() for s in signals]}
