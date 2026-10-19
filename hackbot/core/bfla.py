"""
HackBot BFLA (Broken Function-Level Authorization)
==================================================
Builds a **function inventory** from the corpus and a **role × function
matrix** on top of the differential engine.

Function inventory — a function is ``(method, host, path template)``:

* *privileged by observation*: every 2xx call in the corpus came from an
  identity ranked above the lowest-ranked *authenticated* test identity
  (needing a login is normal; needing a higher role is what counts);
* *privileged by name*: the path names an admin area (``/admin``,
  ``/internal``, ``/manage``, ``/staff`` …), including endpoints that only
  appear in an imported OpenAPI spec;
* *method siblings*: an ``OPTIONS`` request (safe) sent as the highest-ranked
  identity lists the other methods the route accepts (``Allow`` /
  ``Access-Control-Allow-Methods``). Siblings are inventoried, never
  executed automatically.

Role × function matrix — for each privileged function with a safe method:

1. baseline: call it as the highest-ranked identity;
2. **evidence markers** = markers of *other* test identities present in that
   privileged response (an admin listing shows users' emails, a report shows
   another tenant's id …);
3. call it as every lower-ranked identity (including ``anonymous``) and
   judge with the shared differential logic — ``exposed`` only when one of
   those markers comes back, never on status codes alone.

State-changing functions are listed as ``not_run`` — they need ledger-owned
objects and explicit approval (``/diff`` on a concrete exchange).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from hackbot.core.authz_diff import SAFE_METHODS, AuthzDiff, Response, Variant
from hackbot.core.corpus import Corpus, Exchange
from hackbot.core.identities import ANONYMOUS, IdentityVault

PRIVILEGED_PATH_RE = re.compile(
    r"/(admin|administrator|internal|manage|management|staff|backoffice|back-office|"
    r"superuser|root|ops|console|moderation|moderator|system|sysadmin|debug|actuator)(/|$)",
    re.I)
MAX_FUNCTIONS = 20
MAX_SIBLING_PROBES = 20


@dataclass
class Function:
    method: str
    host: str
    template: str
    exchange_ids: List[int] = field(default_factory=list)
    roles_ok: List[str] = field(default_factory=list)  # identities seen with 2xx
    sources: List[str] = field(default_factory=list)
    privileged: bool = False
    reason: str = ""
    siblings: List[str] = field(default_factory=list)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.method, self.host, self.template)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class MatrixRow:
    function: Function
    baseline: Optional[Variant] = None
    markers: List[str] = field(default_factory=list)
    cells: Dict[str, Variant] = field(default_factory=dict)
    note: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"function": self.function.to_dict(),
                "baseline": self.baseline.to_dict() if self.baseline else None,
                "markers": self.markers, "note": self.note,
                "cells": {k: v.to_dict() for k, v in self.cells.items()}}


class BflaTester:
    def __init__(self, corpus: Corpus, vault: IdentityVault,
                 execute: Callable[[str, str], Tuple[int, str]]):
        self.corpus = corpus
        self.vault = vault
        self.diff = AuthzDiff(corpus, vault, execute)
        self.execute = execute

    # ── inventory ────────────────────────────────────────────────────────
    def _authenticated(self) -> List[str]:
        return [n for n in self.vault.names() if n != ANONYMOUS]

    def top_identity(self) -> Optional[str]:
        names = self._authenticated()
        return max(names, key=self.vault.rank) if names else None

    def inventory(self) -> List[Function]:
        funcs: Dict[Tuple[str, str, str], Function] = {}
        for ex in self.corpus.exchanges:
            fn = funcs.setdefault((ex.method, ex.host, ex.template),
                                  Function(ex.method, ex.host, ex.template))
            fn.exchange_ids.append(ex.id)
            if ex.source not in fn.sources:
                fn.sources.append(ex.source)
            if 200 <= ex.status < 300 and ex.identity and ex.identity not in fn.roles_ok:
                fn.roles_ok.append(ex.identity)

        # Compare with the lowest *authenticated* role: needing a login is normal,
        # needing a higher role is what makes a function privileged.
        ranks = [self.vault.rank(n) for n in self._authenticated()]
        lowest = min(ranks) if ranks else 0
        for fn in funcs.values():
            seen = [self.vault.rank(n) for n in fn.roles_ok if n in self.vault.identities]
            if seen and min(seen) > lowest:
                fn.privileged = True
                fn.reason = (f"only seen succeeding for {sorted(fn.roles_ok)} "
                             f"(lowest rank seen {min(seen)} > {lowest})")
            elif PRIVILEGED_PATH_RE.search(fn.template):
                fn.privileged = True
                fn.reason = "path names an administrative area"
        return sorted(funcs.values(), key=lambda f: (not f.privileged, f.template, f.method))

    def _representative(self, fn: Function) -> Optional[Exchange]:
        exs = [self.corpus.get(i) for i in fn.exchange_ids]
        exs = [e for e in exs if e is not None]
        ok = [e for e in exs if 200 <= e.status < 300 and e.identity in self.vault.identities]
        pool = ok or exs
        if not pool:
            return None
        return max(pool, key=lambda e: self.vault.rank(e.identity)
                   if e.identity in self.vault.identities else -1)

    def discover_siblings(self, functions: List[Function],
                          max_probes: int = MAX_SIBLING_PROBES) -> List[Function]:
        """OPTIONS probes (safe) as the top identity; records allowed methods only."""
        top = self.top_identity()
        if top is None:
            return functions
        probed = set()
        for fn in functions:
            route = (fn.host, fn.template)
            if route in probed or len(probed) >= max_probes:
                continue
            ex = self._representative(fn)
            if ex is None:
                continue
            probed.add(route)
            opt = Exchange(id=0, source="options", method="OPTIONS", url=ex.url, host=ex.host,
                           path=ex.path, template=ex.template,
                           request_headers={k: v for k, v in ex.request_headers.items()
                                            if k.lower() == "accept"})
            _, raw = self.execute(self.diff.build_command(opt, top),
                                  f"BFLA: OPTIONS {fn.template} as {top} (method discovery)")
            resp = Response.parse(raw)
            allowed = set()
            for line in resp.headers.splitlines():
                name, _, value = line.partition(":")
                if name.strip().lower() in ("allow", "access-control-allow-methods"):
                    allowed |= {m.strip().upper() for m in value.split(",") if m.strip()}
            known = {f.method for f in functions if (f.host, f.template) == route}
            for f in functions:
                if (f.host, f.template) == route:
                    f.siblings = sorted(allowed - known - {"OPTIONS", "HEAD"})
        return functions

    # ── matrix ───────────────────────────────────────────────────────────
    def matrix(self, functions: Optional[List[Function]] = None,
               max_functions: int = MAX_FUNCTIONS) -> List[MatrixRow]:
        functions = functions if functions is not None else self.inventory()
        top = self.top_identity()
        rows: List[MatrixRow] = []
        for fn in [f for f in functions if f.privileged][:max_functions]:
            row = MatrixRow(fn)
            rows.append(row)
            if top is None:
                row.note = "no authenticated identity to establish a baseline"
                continue
            if fn.method not in SAFE_METHODS:
                row.note = ("not_run: state-changing — needs ledger-owned objects and approval "
                            "(use /diff on a concrete exchange)")
                continue
            ex = self._representative(fn)
            if ex is None:
                row.note = "no exchange to replay"
                continue
            row.url = ex.url
            base = Variant(identity=top, command=self.diff.build_command(ex, top))
            base.step, raw = self.execute(base.command, f"BFLA baseline: {fn.method} "
                                                        f"{fn.template} as {top}")
            row.baseline = base
            if raw.startswith("BLOCKED") or "\nBLOCKED:" in raw:
                base.verdict, base.detail = "blocked", raw.strip()[:300]
                continue
            resp = Response.parse(raw)
            base.status = resp.status
            if not 200 <= resp.status < 300:
                base.verdict, base.detail = "baseline_failed", f"HTTP {resp.status} as {top}"
                continue
            base.verdict = "baseline"
            all_markers = [m for n in self.vault.names() if n != top
                           for m in self.vault.get(n).markers if m]
            row.markers = [m for m in all_markers if m in resp.body]
            if not row.markers:
                base.detail = ("privileged response contains no other identity's markers — "
                               "exposure can't be proven from data on this function")
            top_rank = self.vault.rank(top)
            for name in self.vault.names():
                if name == top or self.vault.rank(name) >= top_rank:
                    continue
                v = Variant(identity=name, command=self.diff.build_command(ex, name))
                v.step, raw = self.execute(v.command, f"BFLA: {fn.method} {fn.template} as {name}")
                self.diff.judge(v, raw, resp.body, f"{top}-only function", row.markers)
                row.cells[name] = v
        return rows

    # ── findings ─────────────────────────────────────────────────────────
    def finding_actions(self, rows: List[MatrixRow]) -> List[Dict[str, Any]]:
        out = []
        for row in rows:
            fn, base = row.function, row.baseline
            if base is None:
                continue
            for name, v in row.cells.items():
                if v.verdict != "exposed" or v.step is None or not v.excerpt:
                    continue
                victim = self.vault.identity_for_marker(v.owner_marker) or ""
                attacker_role = self.vault.get(name).role
                anon = name == ANONYMOUS
                out.append({
                    "action": "finding",
                    "title": (f"{'Auth bypass' if anon else 'BFLA'}: {fn.method} {fn.template} "
                              f"({base.identity}-only function) callable by {name}"),
                    "severity": "Medium",
                    "vuln_class": "auth bypass" if anon else "bfla",
                    "asset": row.url,
                    "behavior": (f"{fn.method} {fn.template} — {fn.reason} — returned HTTP "
                                 f"{v.status} to {name} (step {v.step}) containing "
                                 f"{v.owner_marker!r}, the same data the privileged baseline as "
                                 f"{base.identity} returned (step {base.step})"),
                    "boundary": ("authentication on an administrative function" if anon else
                                 f"function-level authorization: role {attacker_role!r} invoked "
                                 f"a function reserved for {self.vault.get(base.identity).role!r}"),
                    "impact": (f"{name} received privileged data from {fn.template} including "
                               f"{victim or 'another identity'}'s {v.owner_marker}"),
                    "evidence_refs": [{"step": v.step, "excerpt": v.excerpt, "supports": "both"}],
                    "reproduction": (f"privileged baseline: {base.command}\n"
                                     f"low-privilege: {v.command}"),
                    "attacker_identity": name,
                    "victim_identity": victim,
                    "victim_identifier": v.owner_marker,
                    "privileges_required": "none" if anon else attacker_role,
                    "description": ("Found by the role × function matrix. Severity is a "
                                    "placeholder — set it from what the function exposes. "
                                    + (f"Method siblings seen via OPTIONS (not tested): "
                                       f"{', '.join(fn.siblings)}." if fn.siblings else "")),
                })
        return out


def render_matrix(rows: List[MatrixRow], identities: List[str]) -> str:
    """Markdown table: functions × identities."""
    if not rows:
        return "_No privileged functions in the inventory._"
    cols = [i for i in identities]
    head = "| function | " + " | ".join(cols) + " |"
    sep = "|---|" + "---|" * len(cols)
    lines = [head, sep]
    for r in rows:
        cells = []
        for name in cols:
            if r.baseline and r.baseline.identity == name:
                cells.append(f"baseline ({r.baseline.verdict})")
            elif name in r.cells:
                cells.append(r.cells[name].verdict)
            else:
                cells.append("—")
        label = f"{r.function.method} {r.function.template}"
        if r.note:
            label += f" — {r.note.split(':')[0]}"
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines)
