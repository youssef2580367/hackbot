"""
HackBot Identity Vault
======================
Named test identities for multi-account authorization testing — e.g.
``user-a``, ``user-b`` (same role, different owners), ``admin`` and the
built-in ``anonymous``.

Security model:

* Credentials live only in a local YAML file the hunter writes (keep it
  out of git). The AI never sees them: it writes placeholders that the
  runner expands **inside argv at execution time**:

  ``{{cookie:user-b}}``             → ``session=…; csrftoken=…``
  ``{{bearer:user-b}}``             → the bearer token
  ``{{header:user-b:X-Api-Key}}``   → that header's value

  e.g. ``curl -s -H "Cookie: {{cookie:user-b}}" https://api.example.com/me``

* Every captured output is redacted (``<redacted:user-b.cookie.session>``)
  before it reaches the AI, logs, proof gate, reports or RAG memory.
* Only hunter-controlled test accounts belong here. ``max_identities``
  mirrors the program's account limit and loading more is refused.
* The **ownership ledger** records which object IDs belong to which
  identity, so "A read B's object" is a fact the differential engine can
  check instead of a guess.

File format::

    max_identities: 4
    identities:
      user-a:
        role: user
        tenant: t1
        cookies: {session: "..."}
        markers: ["hunter-a@example.com", "1001"]   # how A shows up in responses
        owned: {order: ["5001"], invoice: ["inv_a1"]}
      user-b:
        role: user
        bearer: "..."
        markers: ["hunter-b@example.com", "1002"]
        owned: {order: ["5002"]}
      admin:
        role: admin
        headers: {X-Api-Key: "..."}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ANONYMOUS = "anonymous"
MIN_SECRET_LEN = 6
_PLACEHOLDER_RE = re.compile(
    r"\{\{(cookie|bearer|header):([A-Za-z0-9_.-]+)(?::([A-Za-z0-9_-]+))?\}\}"
)
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")


class IdentityError(ValueError):
    pass


@dataclass
class Identity:
    name: str
    role: str = "user"
    tenant: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    bearer: str = ""
    markers: List[str] = field(default_factory=list)
    owned: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def auth_headers(self) -> Dict[str, str]:
        """HTTP headers that authenticate as this identity."""
        h = dict(self.headers)
        if self.cookies:
            h["Cookie"] = self.cookie_header
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        return h

    def secrets(self) -> List[Tuple[str, str]]:
        """(label, value) for every credential value, longest first."""
        out = [(f"{self.name}.cookie.{k}", v) for k, v in self.cookies.items()]
        out += [(f"{self.name}.header.{k}", v) for k, v in self.headers.items()]
        if self.bearer:
            out.append((f"{self.name}.bearer", self.bearer))
        if self.cookies and len(self.cookies) > 1:
            out.append((f"{self.name}.cookie", self.cookie_header))
        return [(lbl, v) for lbl, v in out if len(v) >= MIN_SECRET_LEN]

    def public_view(self) -> Dict[str, Any]:
        """Everything except credentials — safe for prompts, reports, packets."""
        return {
            "name": self.name, "role": self.role, "tenant": self.tenant,
            "auth": sorted(
                (["cookie"] if self.cookies else []) + (["bearer"] if self.bearer else [])
                + [f"header:{k}" for k in self.headers]
            ),
            "markers": list(self.markers),
            "owned": {k: list(v) for k, v in self.owned.items()},
        }


class IdentityVault:
    def __init__(self, identities: Dict[str, Identity], max_identities: int = 4,
                 source: str = ""):
        if len(identities) > max_identities:
            raise IdentityError(
                f"{len(identities)} identities exceed max_identities={max_identities} "
                "(the program's test-account limit)"
            )
        self.identities = dict(identities)
        self.identities.setdefault(ANONYMOUS, Identity(name=ANONYMOUS, role="anonymous"))
        self.max_identities = max_identities
        self.source = source
        self._secrets = sorted(
            (s for ident in self.identities.values() for s in ident.secrets()),
            key=lambda s: len(s[1]), reverse=True,
        )

    # ── loading ──────────────────────────────────────────────────────────
    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: str = "") -> "IdentityVault":
        if not isinstance(data, dict):
            raise IdentityError("identities file must be a mapping")
        raw = data.get("identities") or {}
        if not isinstance(raw, dict):
            raise IdentityError("'identities' must be a mapping of name → settings")
        idents: Dict[str, Identity] = {}
        for name, cfg in raw.items():
            name = str(name)
            if not _NAME_RE.match(name) or name == ANONYMOUS:
                raise IdentityError(f"invalid identity name: {name!r}")
            cfg = cfg or {}
            idents[name] = Identity(
                name=name,
                role=str(cfg.get("role", "user")),
                tenant=str(cfg.get("tenant", "")),
                cookies={str(k): str(v) for k, v in (cfg.get("cookies") or {}).items()},
                headers={str(k): str(v) for k, v in (cfg.get("headers") or {}).items()},
                bearer=str(cfg.get("bearer", "") or ""),
                markers=[str(m) for m in cfg.get("markers") or []],
                owned={str(k): [str(i) for i in v] for k, v in (cfg.get("owned") or {}).items()},
            )
        return cls(idents, int(data.get("max_identities", 4)), source)

    @classmethod
    def from_file(cls, path: str) -> "IdentityVault":
        p = Path(path).expanduser()
        try:
            data = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            raise IdentityError(f"invalid YAML in {p}: {exc}") from exc
        return cls.from_dict(data, source=str(p))

    # ── lookup ───────────────────────────────────────────────────────────
    def get(self, name: str) -> Identity:
        try:
            return self.identities[name]
        except KeyError:
            raise IdentityError(f"unknown identity {name!r}") from None

    def names(self) -> List[str]:
        return list(self.identities)

    def public_view(self) -> List[Dict[str, Any]]:
        return [i.public_view() for i in self.identities.values()]

    def summary(self) -> str:
        lines = []
        for i in self.identities.values():
            v = i.public_view()
            owned = ", ".join(f"{k}:{'/'.join(ids)}" for k, ids in v["owned"].items()) or "-"
            lines.append(f"- {i.name} (role={i.role}{', tenant=' + i.tenant if i.tenant else ''};"
                         f" auth={'+'.join(v['auth']) or 'none'}; markers={v['markers'] or '-'};"
                         f" owns={owned})")
        return "\n".join(lines)

    # ── ownership ledger ─────────────────────────────────────────────────
    def owner_of(self, object_id: str, obj_type: str = "") -> Optional[str]:
        for ident in self.identities.values():
            for typ, ids in ident.owned.items():
                if (not obj_type or typ == obj_type) and str(object_id) in ids:
                    return ident.name
        return None

    def add_owned(self, name: str, obj_type: str, object_id: str) -> None:
        ident = self.get(name)
        bucket = ident.owned.setdefault(obj_type, [])
        if str(object_id) not in bucket:
            bucket.append(str(object_id))

    # ── placeholders + redaction ─────────────────────────────────────────
    def placeholders_in(self, text: str) -> List[Tuple[str, str, str]]:
        return [(m.group(1), m.group(2), m.group(3) or "") for m in _PLACEHOLDER_RE.finditer(text)]

    def check_placeholders(self, text: str) -> Optional[str]:
        """Return an error message if *text* references unknown credentials."""
        for kind, name, header in self.placeholders_in(text):
            ident = self.identities.get(name)
            if ident is None:
                return f"unknown identity {name!r} in placeholder"
            if kind == "cookie" and not ident.cookies:
                return f"identity {name!r} has no cookies"
            if kind == "bearer" and not ident.bearer:
                return f"identity {name!r} has no bearer token"
            if kind == "header" and header not in ident.headers:
                return f"identity {name!r} has no header {header!r}"
        return None

    def expand(self, text: str) -> str:
        """Substitute placeholders with real credential values."""
        def sub(m: "re.Match[str]") -> str:
            ident = self.get(m.group(2))
            kind = m.group(1)
            if kind == "cookie":
                return ident.cookie_header
            if kind == "bearer":
                return ident.bearer
            return ident.headers[m.group(3) or ""]
        return _PLACEHOLDER_RE.sub(sub, text)

    def redact(self, text: str) -> str:
        if not text:
            return text
        for label, value in self._secrets:
            if value in text:
                text = text.replace(value, f"<redacted:{label}>")
        return text


def has_placeholders(text: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(text or ""))
