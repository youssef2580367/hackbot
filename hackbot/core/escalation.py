"""
HackBot Impact-Escalation Gate
==============================
Classifies commands that go *beyond proving* a vulnerability — dumping data
after SQLi is confirmed, escalating a confirmed RCE, touching PII, changing
server state, brute-forcing credentials, or generating heavy load.

Levels:

* ``NONE``     — proof / recon command, no extra gate.
* ``APPROVAL`` — needs an explicit, per-command human "yes". This level is
  NOT bypassed by ``auto_confirm``; with no interactive approver the command
  is refused.
* ``BLOCK``    — never run automatically (full-database dumps, persistence,
  reverse shells, OS takeover). Programs treat these as rule violations
  regardless of finding quality.

Every APPROVAL/BLOCK decision carries a ``minimal_alternative`` — the
smallest action that still proves impact — which is shown to the human
before they decide.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class EscalationLevel(str, Enum):
    NONE = "none"
    APPROVAL = "approval"
    BLOCK = "block"


@dataclass
class EscalationDecision:
    level: EscalationLevel
    category: str = ""
    reason: str = ""
    minimal_alternative: str = ""

    @property
    def needs_human(self) -> bool:
        return self.level != EscalationLevel.NONE

    def prompt_text(self) -> str:
        lines = [f"IMPACT-ESCALATION [{self.category}]: {self.reason}"]
        if self.minimal_alternative:
            lines.append(f"Minimal proof instead: {self.minimal_alternative}")
        lines.append("Approve only if the program rules allow this step.")
        return "\n".join(lines)


# Default number of records a PII / data sample may contain.
DEFAULT_SAMPLE_LIMIT = 1

_SQLMAP_BLOCK = {
    "--dump-all": "dumps every database",
    "-a": "retrieves everything (--all)",
    "--all": "retrieves everything",
    "--os-pwn": "OS takeover / out-of-band shell",
    "--os-bof": "buffer-overflow exploitation",
    "--priv-esc": "database process privilege escalation",
    "--reg-add": "writes the Windows registry",
    "--reg-del": "deletes Windows registry keys",
    "--file-write": "writes files on the database server",
}
_SQLMAP_APPROVAL = {
    "--dump": "extracts table rows",
    "--passwords": "extracts database password hashes",
    "--os-shell": "interactive OS shell through SQLi",
    "--os-cmd": "runs an OS command through SQLi",
    "--sql-shell": "interactive SQL shell",
    "--sql-query": "arbitrary SQL query",
    "--file-read": "reads files from the database server",
    "--reg-read": "reads the Windows registry",
    "--search": "searches for columns/tables (often PII)",
    "--common-tables": "brute-forces table names",
}

_PII_TABLE_RE = re.compile(
    r"(user|customer|account|member|client|person|people|employee|patient|"
    r"payment|card|order|address|profile|contact|login|credential)",
    re.I,
)

# Reverse shells / persistence — beyond any bug bounty proof.
_BLOCK_PATTERNS = [
    (re.compile(r"/dev/tcp/|/dev/udp/"), "reverse_shell", "bash /dev/tcp reverse shell"),
    (re.compile(r"\b(nc|ncat|netcat)\b[^|]*\s-(e|c)\s"), "reverse_shell", "netcat shell"),
    (re.compile(r"\bmkfifo\b.*\b(nc|ncat|sh)\b"), "reverse_shell", "fifo reverse shell"),
    (re.compile(r"\bbash\s+-i\b"), "reverse_shell", "interactive bash shell"),
    (re.compile(r"pty\.spawn|socket\.socket\(.*connect", re.S), "reverse_shell",
     "scripted reverse shell"),
    (re.compile(r"reverse_tcp|meterpreter|shell_reverse", re.I), "reverse_shell",
     "Metasploit reverse payload"),
    (re.compile(r"authorized_keys"), "persistence", "writes SSH authorized_keys"),
    (re.compile(r"\b(rm\s+-rf|shred|mkfs|dd\s+if=)"), "destructive",
     "destroys data on the target"),
    (re.compile(r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b", re.I), "destructive",
     "drops database objects"),
]

# Possible persistence. These words also appear in ordinary endpoint names
# (/api/adduser), so they ask a human instead of hard-blocking.
_PERSISTENCE_PATTERNS = [
    (re.compile(r"\bcrontab\s+-|/etc/cron"), "installs or edits a cron job"),
    (re.compile(r"\b(useradd|adduser|usermod)\s+-?\w"), "creates/modifies OS users"),
    (re.compile(r"systemctl\s+(enable|start)|/etc/systemd/"), "installs a service"),
]

# Sensitive data an RCE / LFI / SSRF payload might read.
_SENSITIVE_PATTERNS = [
    (re.compile(r"/etc/shadow"), "password hashes"),
    (re.compile(r"id_(rsa|dsa|ecdsa|ed25519)\b"), "private SSH keys"),
    (re.compile(r"\.aws/credentials|\.boto\b"), "cloud credentials"),
    (re.compile(r"169\.254\.169\.254/.*(security-credentials|token)|"
                r"metadata\.google\.internal/.*token|/metadata/identity", re.I),
     "cloud metadata credentials"),
    (re.compile(r"\.env\b|wp-config\.php|config/database\.yml|settings\.py"),
     "application secrets"),
    (re.compile(r"\b(printenv|env)\b\s*($|[|;&'\"])"), "environment secrets"),
    (re.compile(r"\b(linpeas|linenum|winpeas|pspy|mimikatz|lazagne)\b", re.I),
     "post-exploitation tooling"),
]

_RCE_PROOF_HINT = "a single harmless command such as `id`, `hostname` or `whoami`"

_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _tokens(command: str) -> List[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _flag_value(tokens: List[str], *names: str) -> Optional[str]:
    for i, tok in enumerate(tokens):
        for name in names:
            if tok == name and i + 1 < len(tokens):
                return tokens[i + 1]
            if tok.startswith(name + "="):
                return tok.split("=", 1)[1]
    return None


def _has_flag(tokens: List[str], name: str) -> bool:
    return any(t == name or t.startswith(name + "=") for t in tokens)


def _tool(tokens: List[str]) -> str:
    for tok in tokens:
        if tok in ("sudo", "-S"):
            continue
        return tok.rsplit("/", 1)[-1].lower()
    return ""


def _classify_sqlmap(tokens: List[str], sample_limit: int) -> Optional[EscalationDecision]:
    for flag, why in _SQLMAP_BLOCK.items():
        if _has_flag(tokens, flag):
            return EscalationDecision(
                EscalationLevel.BLOCK, "data_extraction",
                f"sqlmap {flag} {why}",
                "prove injection with --banner / --current-user / --current-db, "
                "or --count on one table",
            )
    for flag, why in _SQLMAP_APPROVAL.items():
        if not _has_flag(tokens, flag):
            continue
        reason = f"sqlmap {flag} {why}"
        if flag == "--dump":
            table = _flag_value(tokens, "-T") or ""
            stop = _flag_value(tokens, "--stop")
            if not table:
                return EscalationDecision(
                    EscalationLevel.BLOCK, "data_extraction",
                    "sqlmap --dump without -T dumps whole databases",
                    "name one table with -T and add --start 1 --stop "
                    f"{sample_limit}, or use --count",
                )
            try:
                rows = int(stop) - int(_flag_value(tokens, "--start") or 1) + 1 if stop else None
            except ValueError:
                rows = None
            if rows is None or rows > sample_limit:
                reason += (f" from table '{table}' with no row limit"
                           if rows is None else f" ({rows} rows > sample limit {sample_limit})")
            else:
                reason += f" ({rows} row(s) from '{table}')"
            if _PII_TABLE_RE.search(table):
                reason += " — table likely holds PII"
        alt = (f"--count -T <table>, or --dump -T <table> --start 1 --stop {sample_limit} "
               "and redact the row in the report")
        if flag in ("--os-shell", "--os-cmd"):
            alt = f"--os-cmd with {_RCE_PROOF_HINT}"
        return EscalationDecision(EscalationLevel.APPROVAL, "data_extraction", reason, alt)

    risk = _flag_value(tokens, "--risk")
    if risk and risk.strip() == "3":
        return EscalationDecision(
            EscalationLevel.APPROVAL, "state_change",
            "sqlmap --risk 3 uses OR/UPDATE-style payloads that can modify data",
            "use the default --risk 1 first",
        )
    return None


def classify(command: str, sample_limit: int = DEFAULT_SAMPLE_LIMIT) -> EscalationDecision:
    """Classify *command* by how far beyond proof-of-concept it goes."""
    tokens = _tokens(command)
    tool = _tool(tokens)

    for pattern, category, why in _BLOCK_PATTERNS:
        if pattern.search(command):
            return EscalationDecision(
                EscalationLevel.BLOCK, category, why,
                f"stop at proof of execution: {_RCE_PROOF_HINT}",
            )

    for pattern, why in _PERSISTENCE_PATTERNS:
        if pattern.search(command):
            return EscalationDecision(
                EscalationLevel.APPROVAL, "persistence", why,
                f"stop at proof of execution: {_RCE_PROOF_HINT}",
            )

    if tool == "sqlmap":
        decision = _classify_sqlmap(tokens, sample_limit)
        if decision:
            return decision

    if tool in ("msfconsole", "msfvenom"):
        return EscalationDecision(
            EscalationLevel.APPROVAL, "exploitation",
            f"{tool} runs exploit / payload tooling against the target",
            "reproduce the bug manually with a minimal, non-destructive request",
        )

    if tool in ("hydra", "medusa", "ncrack", "patator", "crackmapexec", "netexec", "nxc"):
        return EscalationDecision(
            EscalationLevel.APPROVAL, "credential_attack",
            f"{tool} brute-forces credentials — never against real users' accounts",
            "test only accounts you own, or demonstrate missing rate limiting "
            "with a handful of requests on your own account",
        )

    for pattern, what in _SENSITIVE_PATTERNS:
        if pattern.search(command):
            return EscalationDecision(
                EscalationLevel.APPROVAL, "sensitive_data",
                f"request reads {what}",
                f"prove access with {_RCE_PROOF_HINT} or a non-secret file "
                "(e.g. /etc/hostname); never exfiltrate secrets",
            )

    if tool in ("curl", "wget", "http", "httpie", "xh"):
        method = (_flag_value(tokens, "-X", "--request") or "").upper()
        if not method and tool == "curl" and any(
            _has_flag(tokens, f) for f in ("-d", "--data", "--data-raw",
                                           "--data-binary", "--data-urlencode",
                                           "-F", "--form", "--json")
        ):
            method = "POST"
        if not method and tool in ("http", "httpie", "xh") and len(tokens) > 1 \
                and tokens[1].upper() in _STATE_METHODS:
            method = tokens[1].upper()
        if method in _STATE_METHODS:
            return EscalationDecision(
                EscalationLevel.APPROVAL, "state_change",
                f"{method} request may change server state",
                "replay against your own test account/object only, or use the "
                "recorded request as evidence",
            )

    if tool == "masscan":
        rate = _flag_value(tokens, "--rate", "--max-rate")
        try:
            if rate and int(rate) > 1000:
                return EscalationDecision(
                    EscalationLevel.APPROVAL, "load",
                    f"masscan --rate {rate} can degrade the target",
                    "use --rate 100 or lower",
                )
        except ValueError:
            pass
    if tool == "nmap" and any(t in ("-T5", "-T 5") for t in tokens):
        return EscalationDecision(
            EscalationLevel.APPROVAL, "load", "nmap -T5 is aggressive", "use -T3 or -T4",
        )
    if tool in ("ffuf", "feroxbuster", "gobuster", "wfuzz"):
        threads = _flag_value(tokens, "-t", "--threads")
        try:
            if threads and int(threads) > 100:
                return EscalationDecision(
                    EscalationLevel.APPROVAL, "load",
                    f"{tool} with {threads} threads can degrade the target",
                    "use 40 threads or fewer and a rate limit",
                )
        except ValueError:
            pass

    return EscalationDecision(EscalationLevel.NONE)
