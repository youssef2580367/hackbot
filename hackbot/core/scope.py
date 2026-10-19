"""
HackBot Scope Enforcement
=========================
Deterministic, fail-closed scope checking for every outbound command the
agent wants to run.

A :class:`ScopePolicy` holds in-scope and out-of-scope rules (exact hosts,
``*.wildcard`` hosts, IPs, CIDRs, and URL prefixes). :func:`extract_targets`
pulls every network target it can find out of a command line (URLs, hosts,
IPs, CIDRs, and the contents of host-list files passed with ``-l``/``-iL``…).
:meth:`ScopePolicy.check_command` combines the two into a
:class:`ScopeDecision`:

* ``ALLOW``   — every extracted target is in scope.
* ``DENY``    — at least one target is out of scope (or explicitly excluded).
* ``UNKNOWN`` — the command uses a network tool but no target could be
  extracted, so scope cannot be proven. Callers must treat this as
  "requires explicit human approval", never as allowed.

Rule semantics (aligned with how bug bounty programs publish scope):

* ``example.com``       — that exact host only.
* ``*.example.com``     — any subdomain of example.com, NOT the apex.
* ``10.0.0.0/24``       — any IP in the network.
* ``https://example.com/api`` — that host, restricted to paths under ``/api``.
* Out-of-scope rules always win over in-scope rules.

Every decision can be appended to a JSONL audit log.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import yaml


class ScopeVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass
class ScopeDecision:
    verdict: ScopeVerdict
    reason: str
    targets: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == ScopeVerdict.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "targets": self.targets,
            "out_of_scope": self.out_of_scope,
        }


# Tools that talk to the network. If one of these runs and no target can be
# extracted, the decision is UNKNOWN (fail closed) rather than ALLOW.
NETWORK_TOOLS = frozenset({
    "nmap", "masscan", "rustscan", "naabu", "nikto", "gobuster", "feroxbuster",
    "sqlmap", "wfuzz", "ffuf", "nuclei", "subfinder", "httpx", "amass",
    "dnsrecon", "dnsenum", "whatweb", "dirb", "dirsearch", "hydra", "medusa",
    "wpscan", "joomscan", "dalfox", "commix", "xsstrike", "arjun", "katana",
    "gau", "waybackurls", "hakrawler", "gospider", "curl", "wget", "http",
    "httpie", "nc", "ncat", "netcat", "socat", "ping", "traceroute", "dig",
    "host", "nslookup", "whois", "sslscan", "sslyze", "testssl", "testssl.sh",
    "enum4linux", "smbclient", "smbmap", "crackmapexec", "netexec", "nxc",
    "ldapsearch", "snmpwalk", "onesixtyone", "msfconsole", "searchsploit",
    "assetfinder", "dnsx", "shuffledns", "puredns", "tlsx", "cdncheck",
    "interactsh-client", "kiterunner", "kr", "graphw00f", "jwt_tool",
    "python", "python3", "ruby", "perl", "node",
})

# Tools that never generate traffic to a target by themselves. searchsploit
# queries a local database even though it is listed above for UNKNOWN safety;
# keep it out of the network set here.
LOCAL_ONLY_TOOLS = frozenset({"searchsploit", "john", "hashcat", "grep", "jq",
                              "cat", "head", "tail", "sort", "uniq", "wc",
                              "awk", "sed", "cut", "tr", "echo", "base64",
                              "xxd", "strings", "file", "ls"})

# Flags whose value is a file containing one target per line.
LIST_FILE_FLAGS = frozenset({
    "-iL", "-l", "-list", "--list", "-L", "-hL", "--hosts-file", "-hosts",
    "-targets", "--targets", "-dL", "-iL-file", "--input-file",
})

# Flags whose value is a local file path, never a target.
FILE_VALUE_FLAGS = frozenset({
    "-o", "-oN", "-oX", "-oG", "-oA", "-oJ", "--output", "-w", "--wordlist",
    "-P", "-U", "--script-args-file", "-r", "--request", "-t", "--templates",
    "-json-export", "-jsonl", "--resume", "-config", "--config", "-c",
    "--data-binary", "--cookie-jar", "-b", "--cacert", "--cert", "--key",
    "-x", "--extensions", "--proxy", "-e",
})

_FILE_EXTENSIONS = (
    ".txt", ".json", ".jsonl", ".xml", ".html", ".htm", ".csv", ".log", ".py",
    ".sh", ".rb", ".pl", ".js", ".yaml", ".yml", ".lst", ".list", ".nmap",
    ".gnmap", ".md", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".nse", ".conf",
    ".cfg", ".ini", ".req", ".pem", ".crt", ".key", ".zip", ".tar", ".gz",
    ".db", ".sqlite", ".out", ".har", ".burp",
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)
_HOST_PORT_RE = re.compile(r"^(?P<host>[^/:\s]+|\[[0-9a-f:]+\]):(?P<port>\d{1,5})$", re.I)
_EMBEDDED_URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s'\"<>]+", re.I)


# ── Rules ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScopeRule:
    """One scope entry."""

    raw: str
    kind: str  # host | wildcard | ip | cidr | url
    host: str = ""
    path_prefix: str = ""
    network: Optional[Any] = None  # ipaddress network for ip/cidr
    port: Optional[int] = None     # None = any port
    scheme: str = ""               # "" = any scheme

    @classmethod
    def parse(cls, entry: str) -> "ScopeRule":
        raw = entry.strip()
        if not raw:
            raise ValueError("empty scope rule")
        value = raw.lower()

        if "://" in value:
            parts = urlsplit(value)
            host = _norm_host(parts.hostname or "")
            if not host:
                raise ValueError(f"invalid URL scope rule: {raw}")
            try:
                port = parts.port
            except ValueError as exc:
                raise ValueError(f"invalid port in scope rule: {raw}") from exc
            scheme = parts.scheme
            path = parts.path.rstrip("/")
            if host.startswith("*."):
                return cls(raw=raw, kind="wildcard", host=host[2:], path_prefix=path,
                           port=port, scheme=scheme)
            ip_net = _as_network(host)
            if ip_net is not None:
                return cls(raw=raw, kind="ip", host=host, path_prefix=path, network=ip_net,
                           port=port, scheme=scheme)
            return cls(raw=raw, kind="url" if path else "host", host=host, path_prefix=path,
                       port=port, scheme=scheme)

        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR scope rule: {raw}") from exc
            return cls(raw=raw, kind="cidr", host=value, network=net)

        ip_net = _as_network(value)
        if ip_net is not None:
            return cls(raw=raw, kind="ip", host=value, network=ip_net)

        # host:port / [v6]:port without a scheme
        m = _HOST_PORT_RE.match(value)
        if m:
            inner = cls.parse(m.group("host").strip("[]"))
            return cls(raw=raw, kind=inner.kind, host=inner.host, network=inner.network,
                       port=_valid_port(m.group("port"), raw))

        if value.startswith("*."):
            base = value[2:].strip(".")
            if not _HOSTNAME_RE.match(base):
                raise ValueError(f"invalid wildcard scope rule: {raw}")
            return cls(raw=raw, kind="wildcard", host=base)

        host = _norm_host(value)
        if not _HOSTNAME_RE.match(host) and host != "localhost":
            raise ValueError(f"invalid host scope rule: {raw}")
        return cls(raw=raw, kind="host", host=host)

    def matches(self, host: str, path: str = "", port: Optional[int] = None,
                scheme: str = "") -> bool:
        host = _norm_host(host)
        if self.port is not None and port != self.port:
            return False  # unknown target port never satisfies a port-bound rule
        if self.scheme and scheme and scheme != self.scheme:
            return False
        if self.kind in ("ip", "cidr"):
            ip = _as_ip(host)
            if ip is None or self.network is None:
                return False
            if ip not in self.network:
                return False
        elif self.kind == "wildcard":
            if not host.endswith("." + self.host):
                return False
        else:  # host / url
            if host != self.host:
                return False

        if self.path_prefix:
            # Case-insensitive: many frameworks (Express, IIS) route /API/x like /api/x,
            # so an exclusion must not be bypassable by changing case.
            norm = "/" + path.lstrip("/") if path else "/"
            norm = norm.split("?", 1)[0].split("#", 1)[0].lower()
            if not (norm == self.path_prefix or norm.startswith(self.path_prefix + "/")):
                return False
        return True


def _norm_host(host: str) -> str:
    """Lowercase, strip trailing dots and IPv6 brackets, IDNA-encode unicode names."""
    host = (host or "").strip().strip("[]").rstrip(".").lower()
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return host
    return host


def _valid_port(value: str, raw: str) -> int:
    port = int(value)
    if not 0 < port < 65536:
        raise ValueError(f"invalid port in scope rule: {raw}")
    return port


DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _as_ip(value: str) -> Optional[Any]:
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def _as_network(value: str) -> Optional[Any]:
    ip = _as_ip(value)
    if ip is None:
        return None
    return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")


# ── Target extraction ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    """A network target found in a command."""

    raw: str
    host: str
    path: str = ""
    is_cidr: bool = False
    port: Optional[int] = None
    scheme: str = ""


def _target_from_token(token: str) -> Optional[Target]:
    tok = token.strip().strip("'\"").rstrip(",;")
    if not tok or tok.startswith("-"):
        return None
    low = tok.lower()

    if "://" in low:
        try:
            parts = urlsplit(tok)
            host = _norm_host(parts.hostname or "")
            port = parts.port
        except ValueError:
            return None
        if not host:
            return None
        scheme = parts.scheme.lower()
        return Target(raw=tok, host=host, path=parts.path or "/",
                      port=port if port is not None else DEFAULT_PORTS.get(scheme),
                      scheme=scheme)

    if "/" in low:
        try:
            ipaddress.ip_network(low, strict=False)
            return Target(raw=tok, host=low, is_cidr=True)
        except ValueError:
            pass
        # host/path without scheme, e.g. example.com/admin
        head, _, rest = low.partition("/")
        if _HOSTNAME_RE.match(head) and not head.endswith(_FILE_EXTENSIONS):
            return Target(raw=tok, host=head, path="/" + rest)
        return None

    m = _HOST_PORT_RE.match(low)
    if m:
        host = _norm_host(m.group("host"))
        if _as_ip(host) is not None or (_HOSTNAME_RE.match(host) or host == "localhost"):
            port = int(m.group("port"))
            return Target(raw=tok, host=host, port=port if 0 < port < 65536 else None)
        return None

    if _as_ip(low) is not None:
        return Target(raw=tok, host=low.strip("[]"))

    if low == "localhost":
        return Target(raw=tok, host=low)

    if _HOSTNAME_RE.match(low) and not low.endswith(_FILE_EXTENSIONS):
        return Target(raw=tok, host=low)
    return None


def _read_list_file(path: str) -> Tuple[List[Target], Optional[str]]:
    """Read a host-list file. Returns (targets, error)."""
    p = Path(path).expanduser()
    if not p.is_file():
        return [], f"target list file not found: {path}"
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError as exc:
        return [], f"cannot read target list {path}: {exc}"
    targets: List[Target] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        t = _target_from_token(line)
        if t is None:
            return [], f"unparseable entry in target list {path}: {line!r}"
        targets.append(t)
    return targets, None


def _split_stages(command: str) -> List[List[str]]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    stages: List[List[str]] = [[]]
    for tok in tokens:
        if tok == "|":
            stages.append([])
        else:
            stages[-1].append(tok)
    return [s for s in stages if s]


def _stage_tool(argv: List[str]) -> str:
    i = 0
    while i < len(argv) and argv[i] in ("sudo", "-S", "env", "timeout"):
        i += 1
        # skip timeout duration / env assignments
        while i < len(argv) and (re.match(r"^\d+[smh]?$", argv[i]) or "=" in argv[i]):
            i += 1
    return os.path.basename(argv[i]).lower() if i < len(argv) else ""


# Flags whose value is request data / headers. URLs inside them are payloads
# the *target server* may fetch (SSRF, open redirect, OOB callbacks), not
# hosts HackBot sends traffic to, so they are recorded but not scope-checked.
PAYLOAD_VALUE_FLAGS = frozenset({
    "-d", "--data", "--data-raw", "--data-urlencode", "--data-ascii", "-H",
    "--header", "-F", "--form", "--form-string", "--cookie", "-A",
    "--user-agent", "-e", "--referer", "--json",
})

INTERPRETERS = frozenset({"python", "python3", "ruby", "perl", "node", "bash", "sh"})


@dataclass
class Extraction:
    targets: List[Target] = field(default_factory=list)
    payload_urls: List[str] = field(default_factory=list)
    uses_network: bool = False
    errors: List[str] = field(default_factory=list)


def _script_targets(path: str) -> List[Target]:
    """URLs hard-coded in a local script the agent wants to run."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    found = []
    for url in _EMBEDDED_URL_RE.findall(text):
        t = _target_from_token(url.rstrip(")]}.,'\""))
        if t:
            found.append(t)
    return found


def extract_targets(command: str) -> Extraction:
    """Extract every network target referenced by a command line."""
    result = Extraction()
    for argv in _split_stages(command):
        tool = _stage_tool(argv)
        if tool in NETWORK_TOOLS and tool not in LOCAL_ONLY_TOOLS:
            result.uses_network = True
        if tool in INTERPRETERS:
            result.uses_network = True

        mode = ""  # "" | "skip" | "list" | "payload"
        for idx, tok in enumerate(argv):
            if idx == 0 or (not mode and os.path.basename(tok).lower() == tool
                            and idx <= 2):
                continue

            if mode:
                cur, mode = mode, ""
                if cur == "list":
                    t, err = _read_list_file(tok)
                    result.targets.extend(t)
                    if err:
                        result.errors.append(err)
                elif cur == "payload":
                    result.payload_urls.extend(_EMBEDDED_URL_RE.findall(tok))
                elif cur == "code":
                    for url in _EMBEDDED_URL_RE.findall(tok):
                        t = _target_from_token(url)
                        if t:
                            result.targets.append(t)
                continue

            if tool in INTERPRETERS and tok in ("-c", "-e") and idx + 1 < len(argv):
                mode = "code"
                continue

            if tok.startswith("-"):
                flag, eq, value = tok.partition("=")
                if flag in LIST_FILE_FLAGS:
                    if eq:
                        t, err = _read_list_file(value)
                        result.targets.extend(t)
                        if err:
                            result.errors.append(err)
                    else:
                        mode = "list"
                    continue
                if flag in PAYLOAD_VALUE_FLAGS:
                    if eq:
                        result.payload_urls.extend(_EMBEDDED_URL_RE.findall(value))
                    else:
                        mode = "payload"
                    continue
                if flag in FILE_VALUE_FLAGS:
                    if not eq:
                        mode = "skip"
                    continue
                if not eq:
                    continue  # boolean flag, or a flag whose value is next token
                tok = value

            # Interpreter running a local script: scan the script body.
            if tool in INTERPRETERS and os.path.isfile(tok):
                result.targets.extend(_script_targets(tok))
                continue

            # URLs embedded inside a larger argument (e.g. python -c "...")
            if "://" in tok and not tok.lower().startswith(
                ("http://", "https://", "ws://", "wss://", "ftp://")
            ):
                for url in _EMBEDDED_URL_RE.findall(tok):
                    t = _target_from_token(url)
                    if t:
                        result.targets.append(t)
                continue

            if "://" not in tok and os.path.exists(tok):
                continue  # a local file / directory argument
            t = _target_from_token(tok)
            if t:
                result.targets.append(t)
    return result


# ── Policy ───────────────────────────────────────────────────────────────────


class ScopePolicy:
    """In/out-of-scope rules plus decision logic."""

    def __init__(
        self,
        in_scope: Iterable[str] = (),
        out_of_scope: Iterable[str] = (),
        name: str = "",
        source: str = "",
    ):
        self.name = name
        self.source = source
        self.in_scope: List[ScopeRule] = [ScopeRule.parse(r) for r in in_scope if r.strip()]
        self.out_of_scope: List[ScopeRule] = [
            ScopeRule.parse(r) for r in out_of_scope if r.strip()
        ]

    # ── construction ─────────────────────────────────────────────────────
    @classmethod
    def from_target(cls, target: str) -> "ScopePolicy":
        """Strict default policy: only the exact host of *target*."""
        t = _target_from_token(target.strip())
        if t is None:
            raise ValueError(f"cannot derive scope from target: {target!r}")
        rule = t.host if not t.is_cidr else t.raw
        return cls(in_scope=[rule], name=f"auto:{rule}", source="target")

    @classmethod
    def from_text(cls, text: str, source: str = "") -> "ScopePolicy":
        """Parse a scope definition.

        Accepts YAML/JSON (``in_scope:`` / ``out_of_scope:`` lists, optional
        ``name:``) or plain text: one rule per line, ``!`` or ``-`` prefix for
        out-of-scope, ``#`` for comments. Sections ``[in]`` / ``[out]`` are
        also understood.
        """
        stripped = text.strip()
        if stripped.startswith("{") or re.search(r"^\s*(in_scope|out_of_scope)\s*:", text, re.M):
            data = yaml.safe_load(text) or {}
            if not isinstance(data, dict):
                raise ValueError("scope file must be a mapping with in_scope/out_of_scope")
            return cls(
                in_scope=[str(x) for x in data.get("in_scope", []) or []],
                out_of_scope=[str(x) for x in data.get("out_of_scope", []) or []],
                name=str(data.get("name", "")),
                source=source,
            )

        ins: List[str] = []
        outs: List[str] = []
        section = "in"
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            low = line.lower()
            if low in ("[in]", "[in_scope]", "[in-scope]"):
                section = "in"
                continue
            if low in ("[out]", "[out_of_scope]", "[out-of-scope]"):
                section = "out"
                continue
            if line.startswith("!"):
                outs.append(line[1:].strip())
            elif section == "out":
                outs.append(line)
            else:
                ins.append(line)
        return cls(in_scope=ins, out_of_scope=outs, source=source)

    @classmethod
    def from_file(cls, path: str) -> "ScopePolicy":
        p = Path(path).expanduser()
        return cls.from_text(p.read_text(), source=str(p))

    @classmethod
    def from_rules_string(cls, rules: str) -> Optional["ScopePolicy"]:
        """Parse a comma/space separated rule list (e.g. the CLI --scope value).

        Returns None when the string is free text rather than scope rules,
        so legacy descriptive ``--scope`` values keep working.
        """
        parts = [p for p in re.split(r"[,\s]+", rules.strip()) if p]
        if not parts:
            return None
        ins: List[str] = []
        outs: List[str] = []
        for part in parts:
            neg = part.startswith("!")
            body = part[1:] if neg else part
            try:
                ScopeRule.parse(body)
            except ValueError:
                return None
            (outs if neg else ins).append(body)
        if not ins:
            return None
        return cls(in_scope=ins, out_of_scope=outs, source="rules")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "in_scope": [r.raw for r in self.in_scope],
            "out_of_scope": [r.raw for r in self.out_of_scope],
        }

    def summary(self) -> str:
        ins = ", ".join(r.raw for r in self.in_scope) or "(none)"
        outs = ", ".join(r.raw for r in self.out_of_scope) or "(none)"
        return f"In scope: {ins}\nOut of scope: {outs}"

    # ── decisions ────────────────────────────────────────────────────────
    def check_target(self, host: str, path: str = "", is_cidr: bool = False,
                     port: Optional[int] = None, scheme: str = "") -> Tuple[bool, str]:
        host = host.lower()
        if is_cidr:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                return False, f"invalid network {host}"
            for rule in self.out_of_scope:
                if rule.network is not None and net.overlaps(rule.network):
                    return False, f"{host} overlaps out-of-scope {rule.raw}"
            for rule in self.in_scope:
                if rule.network is not None and net.subnet_of(rule.network):  # type: ignore[arg-type]
                    return True, f"{host} within {rule.raw}"
            return False, f"{host} is not fully inside any in-scope network"

        where = f"{host}{':' + str(port) if port else ''}"
        for rule in self.out_of_scope:
            # out-of-scope rules with a path / port only exclude that path / port
            if rule.matches(host, path, port, scheme):
                return False, f"{where}{path} matches out-of-scope rule {rule.raw}"
        for rule in self.in_scope:
            if rule.matches(host, path, port, scheme):
                return True, f"{where} matches {rule.raw}"
        return False, f"{where}{path if path not in ('', '/') else ''} is not in scope"

    def check_raw_target(self, target: str) -> Tuple[bool, str]:
        """Check a user-supplied target string (URL, host, IP or CIDR)."""
        t = _target_from_token(target.strip())
        if t is None:
            return False, f"cannot parse target {target!r}"
        return self.check_target(t.host, t.path, t.is_cidr, t.port, t.scheme)

    def check_command(self, command: str) -> ScopeDecision:
        ext = extract_targets(command)
        if ext.errors:
            return ScopeDecision(
                ScopeVerdict.DENY,
                "; ".join(ext.errors),
                targets=[t.raw for t in ext.targets],
            )
        if not ext.targets:
            if ext.uses_network:
                return ScopeDecision(
                    ScopeVerdict.UNKNOWN,
                    "network tool with no target HackBot can verify against scope",
                )
            return ScopeDecision(ScopeVerdict.ALLOW, "no network targets")

        bad: List[str] = []
        reasons: List[str] = []
        for t in ext.targets:
            ok, why = self.check_target(t.host, t.path, t.is_cidr, t.port, t.scheme)
            if not ok:
                bad.append(t.raw)
                reasons.append(why)
        if bad:
            return ScopeDecision(
                ScopeVerdict.DENY,
                "; ".join(reasons),
                targets=[t.raw for t in ext.targets],
                out_of_scope=bad,
            )
        return ScopeDecision(
            ScopeVerdict.ALLOW,
            "all targets in scope",
            targets=[t.raw for t in ext.targets],
        )


# ── Audit log ────────────────────────────────────────────────────────────────


class ScopeAuditLog:
    """Append-only JSONL log of every scope decision."""

    def __init__(self, path: Optional[Path] = None):
        if path is None:
            from hackbot.config import LOGS_DIR

            path = LOGS_DIR / "scope_audit.jsonl"
        self.path = Path(path)

    def record(self, command: str, decision: ScopeDecision, action: str) -> None:
        entry = {
            "ts": time.time(),
            "command": command,
            "action": action,
            **decision.to_dict(),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
