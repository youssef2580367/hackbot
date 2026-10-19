"""
HackBot security boundary types
===============================
Every authorization finding names *which* boundary was crossed, derived from
facts in the identity vault rather than from prose:

* ``authentication``     — an anonymous request reached protected data
* ``tenant_isolation``   — attacker and victim belong to different tenants
* ``function_level``     — a lower role invoked a higher role's function
* ``object_level``       — same role, another user's object
* ``session_lifecycle``  — credentials kept working after a lifecycle event
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from hackbot.core.identities import ANONYMOUS, IdentityVault


class BoundaryType(str, Enum):
    AUTHENTICATION = "authentication"
    TENANT_ISOLATION = "tenant_isolation"
    FUNCTION_LEVEL = "function_level"
    OBJECT_LEVEL = "object_level"
    SESSION_LIFECYCLE = "session_lifecycle"


def _tenant(vault: Optional[IdentityVault], name: str) -> str:
    if vault is None or name not in vault.identities:
        return ""
    return vault.get(name).tenant


def annotate_boundary(action: Dict[str, Any], vault: Optional[IdentityVault]) -> Dict[str, Any]:
    """Set boundary_type / tenants on an engine-built finding action (in place)."""
    attacker = str(action.get("attacker_identity", ""))
    victim = str(action.get("victim_identity", ""))
    a_tenant, v_tenant = _tenant(vault, attacker), _tenant(vault, victim)
    action["attacker_tenant"], action["victim_tenant"] = a_tenant, v_tenant
    vclass = str(action.get("vuln_class", "")).lower()

    if action.get("boundary_type") == BoundaryType.SESSION_LIFECYCLE.value:
        return action
    if attacker == ANONYMOUS:
        action["boundary_type"] = BoundaryType.AUTHENTICATION.value
    elif a_tenant and v_tenant and a_tenant != v_tenant:
        action["boundary_type"] = BoundaryType.TENANT_ISOLATION.value
        action["boundary"] = (f"tenant isolation: identity in tenant {a_tenant!r} reached "
                              f"data of tenant {v_tenant!r}")
        title = str(action.get("title", ""))
        if not title.lower().startswith("cross-tenant"):
            action["title"] = f"Cross-tenant {title}"
    elif vclass == "bfla":
        action["boundary_type"] = BoundaryType.FUNCTION_LEVEL.value
    else:
        action["boundary_type"] = BoundaryType.OBJECT_LEVEL.value
    return action
