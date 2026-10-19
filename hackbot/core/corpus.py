"""
HackBot Request Corpus
======================
One normalized store of HTTP exchanges that every authorization / logic
module reads from, instead of crawling blindly.

Sources: HackBot's own proxy, HAR files (browser / Burp / ZAP exports) and
OpenAPI 3 / Swagger 2 specs (request shapes only, no responses).

On import each exchange is:

1. **scope-filtered** — out-of-scope hosts are counted and dropped;
2. **attributed** to a test identity when its Cookie / Authorization /
   header values match one in the identity vault;
3. **redacted** — credential values are replaced before storage;
4. **templated** — ``/v1/orders/5002`` → ``/v1/orders/{int}`` — and its
   parameters typed (int, uuid, hex, email, token, …) so object-ID
   candidates for BOLA testing can be listed.
"""

from __future__ import annotations

import base64
import itertools
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import yaml

MAX_BODY = 200_000

_INT_RE = re.compile(r"^\d{1,19}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}={0,2}$")
_ID_NAME_RE = re.compile(r"(^|_|-)(id|uuid|guid|uid|pk|key|ref|slug|no|number)$|Id$|ID$", re.I)

_ID_TYPES = ("int", "uuid", "hex", "token")
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    v = str(value)
    if _INT_RE.match(v):
        return "int"
    if _UUID_RE.match(v):
        return "uuid"
    if _HEX_RE.match(v):
        return "hex"
    if _EMAIL_RE.match(v):
        return "email"
    if _TOKEN_RE.match(v) and any(c.isdigit() for c in v):
        return "token"
    return "string"


def path_template(path: str) -> Tuple[str, List[Tuple[int, str, str]]]:
    """Return (template, [(segment index, value, type)]) for variable segments."""
    parts = path.split("/")
    variables: List[Tuple[int, str, str]] = []
    out = []
    for i, seg in enumerate(parts):
        typ = value_type(seg) if seg else "string"
        if typ in ("int", "uuid", "hex", "token", "email"):
            out.append("{" + typ + "}")
            variables.append((i, seg, typ))
        else:
            out.append(seg)
    return "/".join(out) or "/", variables


@dataclass
class Param:
    name: str
    location: str  # path | query | body | json
    value: str
    type: str

    @property
    def is_id_candidate(self) -> bool:
        return self.type in _ID_TYPES and (
            self.location == "path" or bool(_ID_NAME_RE.search(self.name))
        )


@dataclass
class Exchange:
    id: int
    source: str
    method: str
    url: str
    host: str
    path: str
    template: str
    identity: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    params: List[Param] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Exchange":
        d = dict(d)
        d["params"] = [Param(**p) for p in d.get("params", [])]
        return cls(**d)


def _flatten_json(obj: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten_json(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for v in obj[:20]:
            yield from _flatten_json(v, f"{prefix}[]")
    else:
        yield prefix, obj


def _extract_params(path: str, query: str, body: str, content_type: str) -> List[Param]:
    params: List[Param] = []
    _, variables = path_template(path)
    segs = path.split("/")
    for idx, value, typ in variables:
        name = segs[idx - 1] if idx > 0 and segs[idx - 1] else f"seg{idx}"
        params.append(Param(name=f"{name}#{idx}", location="path", value=value, type=typ))
    for k, v in parse_qsl(query, keep_blank_values=True):
        params.append(Param(k, "query", v, value_type(v)))
    if body:
        if "json" in content_type.lower() or body.lstrip().startswith(("{", "[")):
            try:
                for k, v in _flatten_json(json.loads(body)):
                    if v is not None and not isinstance(v, (dict, list)):
                        params.append(Param(k, "json", str(v), value_type(v)))
            except (ValueError, TypeError):
                pass
        elif "=" in body and "\n" not in body.strip():
            for k, v in parse_qsl(body, keep_blank_values=True):
                params.append(Param(k, "body", v, value_type(v)))
    return params


class Corpus:
    """In-memory corpus with optional JSONL persistence."""

    def __init__(self, scope_policy: Any = None, identity_vault: Any = None,
                 path: Optional[Path] = None):
        self.scope_policy = scope_policy
        self.identity_vault = identity_vault
        self.path = Path(path) if path else None
        self.exchanges: List[Exchange] = []
        self.dropped_out_of_scope = 0
        self._ids = itertools.count(1)
        if self.path and self.path.is_file():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    ex = Exchange.from_dict(json.loads(line))
                    self.exchanges.append(ex)
            self._ids = itertools.count(max((e.id for e in self.exchanges), default=0) + 1)

    # ── add ──────────────────────────────────────────────────────────────
    def add(
        self, source: str, method: str, url: str,
        request_headers: Optional[Dict[str, str]] = None, request_body: str = "",
        status: int = 0, response_headers: Optional[Dict[str, str]] = None,
        response_body: str = "", identity: str = "", attribute: bool = True,
    ) -> Optional[Exchange]:
        if not urlsplit(url).hostname:
            return None
        if self.scope_policy is not None and not self.scope_policy.check_raw_target(url)[0]:
            self.dropped_out_of_scope += 1
            return None
        req_h = {str(k): str(v) for k, v in (request_headers or {}).items()}
        if not identity and attribute:
            identity = self._attribute(req_h, url, request_body)
        # Redact first: everything stored or parsed below is credential-free.
        redact = self.identity_vault.redact if self.identity_vault else (lambda x: x)
        url, body = redact(url), redact(request_body[:MAX_BODY])
        parts = urlsplit(url)
        ctype = next((v for k, v in req_h.items() if k.lower() == "content-type"), "")
        path = parts.path or "/"
        ex = Exchange(
            id=next(self._ids), source=source, method=method.upper(), url=url,
            host=(parts.hostname or "").lower(), path=path, template=path_template(path)[0],
            identity=identity,
            request_headers={k: redact(v) for k, v in req_h.items()},
            request_body=body, status=int(status or 0),
            response_headers={str(k): redact(str(v)) for k, v in (response_headers or {}).items()},
            response_body=redact(response_body[:MAX_BODY]),
            params=_extract_params(path, parts.query, body, ctype),
        )
        self.exchanges.append(ex)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a") as f:
                f.write(json.dumps(ex.to_dict()) + "\n")
        return ex

    def _attribute(self, headers: Dict[str, str], url: str = "", body: str = "") -> str:
        """Which vault identity sent this request (credential match in headers, URL or body)."""
        vault = self.identity_vault
        if vault is None:
            return ""
        joined = "\n".join(list(headers.values()) + [url, body])
        for name in vault.names():
            ident = vault.get(name)
            values = list(ident.cookies.values()) + list(ident.headers.values())
            values += [ident.bearer] if ident.bearer else []
            if values and any(v and v in joined for v in values):
                return name
        has_auth = any(k.lower() in ("cookie", "authorization") for k in headers)
        return "" if has_auth else "anonymous"

    # ── importers ────────────────────────────────────────────────────────
    def import_har(self, path: str, source: str = "har") -> int:
        data = json.loads(Path(path).expanduser().read_text(errors="replace"))
        n = 0
        for entry in (data.get("log") or {}).get("entries", []):
            req, resp = entry.get("request") or {}, entry.get("response") or {}
            content = resp.get("content") or {}
            body = content.get("text") or ""
            if content.get("encoding") == "base64":
                try:
                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                except ValueError:
                    body = ""
            ex = self.add(
                source, req.get("method", "GET"), req.get("url", ""),
                {h["name"]: h["value"] for h in req.get("headers", []) if "name" in h},
                (req.get("postData") or {}).get("text", "") or "",
                resp.get("status", 0),
                {h["name"]: h["value"] for h in resp.get("headers", []) if "name" in h},
                body,
            )
            n += ex is not None
        return n

    def import_proxy(self, proxy_engine: Any) -> int:
        n = 0
        for r in reversed(proxy_engine.get_traffic()):
            url = r.url if r.url.startswith("http") else \
                f"{'https' if r.is_https else 'http'}://{r.host}{r.path}"
            ex = self.add("hackbot-proxy", r.method, url, r.request_headers, r.request_body,
                          r.status_code, r.response_headers, r.response_body)
            n += ex is not None
        return n

    def import_openapi(self, path: str, base_url: str = "") -> int:
        text = Path(path).expanduser().read_text(errors="replace")
        spec = json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(text)
        if not isinstance(spec, dict):
            raise ValueError("not an OpenAPI/Swagger document")
        if not base_url:
            if spec.get("servers"):
                base_url = str(spec["servers"][0].get("url", ""))
            elif spec.get("host"):
                scheme = (spec.get("schemes") or ["https"])[0]
                base_url = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
        if "://" not in base_url:
            raise ValueError("spec has no absolute server URL; pass base_url")
        n = 0
        for p, ops in (spec.get("paths") or {}).items():
            for method, op in (ops or {}).items():
                if method.lower() not in _HTTP_METHODS:
                    continue
                # Placeholder example values keep templates/params typed.
                concrete = re.sub(r"\{[^}]+\}", "1", p)
                ex = self.add("openapi", method, base_url.rstrip("/") + concrete,
                              attribute=False)
                if ex is None:
                    continue
                ex.template = re.sub(r"\{[^}]+\}", "{param}", p)
                ex.params = [Param(str(prm.get("name")), str(prm.get("in", "")), "",
                                   (prm.get("schema") or {}).get("type", prm.get("type", "")))
                             for prm in (op or {}).get("parameters", []) if isinstance(prm, dict)]
                n += 1
        return n

    # ── queries ──────────────────────────────────────────────────────────
    def endpoints(self) -> List[Dict[str, Any]]:
        groups: Dict[Tuple[str, str, str], List[Exchange]] = {}
        for ex in self.exchanges:
            groups.setdefault((ex.method, ex.host, ex.template), []).append(ex)
        out = []
        for (method, host, template), exs in sorted(groups.items()):
            out.append({
                "method": method, "host": host, "template": template, "count": len(exs),
                "identities": sorted({e.identity for e in exs if e.identity}),
                "statuses": sorted({e.status for e in exs if e.status}),
                "sources": sorted({e.source for e in exs}),
                "params": sorted({p.name for e in exs for p in e.params}),
            })
        return out

    def id_candidates(self) -> List[Dict[str, Any]]:
        """Parameters that look like object references (BOLA test inputs)."""
        out = []
        for ex in self.exchanges:
            for p in ex.params:
                if p.is_id_candidate and p.value:
                    owner = self.identity_vault.owner_of(p.value) if self.identity_vault else None
                    out.append({"exchange": ex.id, "method": ex.method, "template": ex.template,
                                "param": p.name, "location": p.location, "value": p.value,
                                "type": p.type, "sent_by": ex.identity, "owner": owner})
        return out

    def search(self, term: str) -> List[Exchange]:
        t = term.lower()
        return [e for e in self.exchanges if t in e.url.lower() or t in e.template.lower()
                or t in e.method.lower()]

    def get(self, exchange_id: int) -> Optional[Exchange]:
        return next((e for e in self.exchanges if e.id == exchange_id), None)
