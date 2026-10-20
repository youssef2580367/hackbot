"""
HackBot lab mode
================
Pre-authorised rules of engagement for **isolated local labs only**.

Autonomous benchmarking needs state-changing requests (log in, register a
test account, add to basket …), which the escalation gate normally sends to
a human. ``LabApprover`` answers that gate automatically, but only:

* when every in-scope rule is loopback (``localhost``, ``127.0.0.0/8``,
  ``::1``) — it refuses to exist for any other scope;
* for the escalation categories explicitly allowed (default: only
  ``state_change``). Data extraction, secret reads, credential attacks,
  load, exploitation tooling and persistence are still refused, and
  hard-blocked categories never reach an approver at all;
* never for "scope unverified" commands.

Every decision is appended to an audit log.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Iterable, Optional

from hackbot.core.scope import ScopePolicy

LOOPBACK_NAMES = {"localhost", "localhost.localdomain"}
DEFAULT_CATEGORIES = ("state_change",)
_CATEGORY_RE = re.compile(r"IMPACT-ESCALATION \[(\w+)\]")


def _is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def is_loopback_policy(policy: ScopePolicy) -> bool:
    if not policy.in_scope:
        return False
    for rule in policy.in_scope:
        if rule.kind == "wildcard":
            return False
        if rule.kind == "cidr":
            if rule.network is None or not rule.network.subnet_of(
                    ipaddress.ip_network("127.0.0.0/8") if rule.network.version == 4
                    else ipaddress.ip_network("::1/128")):
                return False
            continue
        if not _is_loopback_host(rule.host):
            return False
    return True


class LabApprover:
    """``on_approve`` callback for loopback-only labs."""

    def __init__(self, policy: ScopePolicy, categories: Iterable[str] = DEFAULT_CATEGORIES,
                 audit_path: Optional[Path] = None):
        if not is_loopback_policy(policy):
            raise ValueError("lab mode requires every in-scope rule to be a loopback host")
        self.categories = frozenset(categories)
        self.audit_path = Path(audit_path) if audit_path else None
        self.decisions: list = []

    def __call__(self, command: str, reason: str) -> bool:
        m = _CATEGORY_RE.search(reason or "")
        category = m.group(1) if m else ("scope_unverified" if "SCOPE UNVERIFIED" in (reason or "")
                                         else "unknown")
        approved = category in self.categories
        entry = {"ts": time.time(), "category": category, "approved": approved,
                 "command": command[:500]}
        self.decisions.append(entry)
        if self.audit_path is not None:
            try:
                self.audit_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.audit_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError:
                pass
        return approved
