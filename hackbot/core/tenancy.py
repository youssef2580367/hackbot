"""
HackBot cross-tenant leak scan
==============================
Looks for tenant-isolation failures that need no ID substitution at all: an
identity's *own* normal request (a list, search, dashboard, export …)
returning data that belongs to an identity in **another tenant**.

1. Passive: scan every corpus response sent by identity X (tenant T1) for
   markers of identities whose tenant is not T1 → lead.
2. Confirm: re-send that same request as X through the gated runner (GET /
   HEAD only), so the evidence is HackBot's own capture, and require the
   foreign marker in the 2xx response.

Identities without a tenant are ignored — isolation can't be judged without
knowing who belongs where.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

from hackbot.core.authz_diff import SAFE_METHODS, AuthzDiff, Response, _excerpt
from hackbot.core.corpus import Corpus
from hackbot.core.identities import ANONYMOUS, IdentityVault


@dataclass
class TenantLead:
    exchange_id: int
    identity: str
    tenant: str
    victim: str
    victim_tenant: str
    marker: str
    method: str
    url: str
    template: str
    status: str = "lead"          # lead | confirmed | not_reproduced | blocked | skipped
    step: int = 0
    excerpt: str = ""
    command: str = ""
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class TenantScanner:
    def __init__(self, corpus: Corpus, vault: IdentityVault,
                 execute: Callable[[str, str], Tuple[int, str]]):
        self.corpus = corpus
        self.vault = vault
        self.diff = AuthzDiff(corpus, vault, execute)
        self.execute = execute

    def leads(self) -> List[TenantLead]:
        tenants = {n: self.vault.get(n).tenant for n in self.vault.names()
                   if n != ANONYMOUS and self.vault.get(n).tenant}
        out: List[TenantLead] = []
        seen = set()
        for ex in self.corpus.exchanges:
            own_tenant = tenants.get(ex.identity)
            if not own_tenant or not 200 <= ex.status < 300:
                continue
            for other, other_tenant in tenants.items():
                if other_tenant == own_tenant:
                    continue
                own = set(self.vault.get(ex.identity).markers)
                marker = next((m for m in self.vault.get(other).markers
                               if m and m not in own and m in ex.response_body), "")
                key = (ex.method, ex.template, ex.identity, other)
                if marker and key not in seen:
                    seen.add(key)
                    out.append(TenantLead(ex.id, ex.identity, own_tenant, other, other_tenant,
                                          marker, ex.method, ex.url, ex.template))
        return out

    def confirm(self, leads: List[TenantLead]) -> List[TenantLead]:
        for lead in leads:
            if lead.method not in SAFE_METHODS:
                lead.status = "skipped"
                lead.detail = "state-changing request — confirm manually with approval"
                continue
            ex = self.corpus.get(lead.exchange_id)
            lead.command = self.diff.build_command(ex, lead.identity)
            lead.step, raw = self.execute(
                lead.command, f"tenant check: {lead.identity} ({lead.tenant}) re-requests "
                              f"{lead.template}")
            if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
                lead.status, lead.detail = "blocked", raw.strip()[:300]
                continue
            resp = Response.parse(raw)
            if 200 <= resp.status < 300 and lead.marker in resp.body:
                lead.status = "confirmed"
                lead.excerpt = _excerpt(resp.body, lead.marker)
            else:
                lead.status = "not_reproduced"
                lead.detail = f"HTTP {resp.status}; foreign marker not in the fresh response"
        return leads

    def finding_actions(self, leads: List[TenantLead]) -> List[Dict[str, Any]]:
        out = []
        for lead in leads:
            if lead.status != "confirmed" or not lead.excerpt:
                continue
            out.append({
                "action": "finding",
                "title": (f"{lead.method} {lead.template} returns tenant {lead.victim_tenant!r} "
                          f"data to tenant {lead.tenant!r}"),
                "severity": "Medium",
                "vuln_class": "bola",
                "asset": lead.url,
                "behavior": (f"{lead.identity} (tenant {lead.tenant!r}) sent its own "
                             f"{lead.method} {lead.url}; the HTTP 2xx response (step "
                             f"{lead.step}) contains {lead.victim}'s marker {lead.marker!r} "
                             f"(tenant {lead.victim_tenant!r})"),
                "boundary": "tenant isolation",
                "impact": (f"{lead.identity} received {lead.victim}'s data ({lead.marker}) "
                           f"belonging to tenant {lead.victim_tenant!r}"),
                "evidence_refs": [{"step": lead.step, "excerpt": lead.excerpt,
                                   "supports": "both"}],
                "reproduction": lead.command,
                "attacker_identity": lead.identity,
                "victim_identity": lead.victim,
                "victim_identifier": lead.marker,
                "privileges_required": self.vault.get(lead.identity).role,
                "description": ("Found by the cross-tenant leak scan: the identity's own request, "
                                "no ID substitution. Severity is a placeholder."),
            })
        return out
