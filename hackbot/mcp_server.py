"""
HackBot MCP server
==================
Exposes HackBot's evidence pipeline as MCP tools so a Claude Code agent can
hunt through HackBot — and *only* through HackBot: every request goes through
scope enforcement, the escalation gate (lab-mode approver when enabled),
credential redaction, the request budget, and is recorded as a step the
proof gate can cite.

    python -m hackbot.mcp_server --scope scope.yaml [--identities ids.yaml]
        [--lab-mode] [--budget 800] [--run-dir runs/x]

Claude Code (subscription) launches it over stdio from an MCP config file.
No Anthropic API key is involved.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch
from urllib.parse import urljoin, urlsplit

from hackbot.config import (AgentConfig, AIConfig, HackBotConfig, ScopeConfig,
                            ValidationConfig)
from hackbot.core.authz_diff import Response
from hackbot.core.engine import AIEngine
from hackbot.core.identities import ANONYMOUS, Identity, IdentityVault
from hackbot.core.lab_mode import LabApprover
from hackbot.core.scope import ScopeAuditLog, ScopePolicy

BODY_LIMIT = 20_000
_PATH_RE = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_\-.~%]+/)*[A-Za-z0-9_\-.~%{}:]*(?:\?[^"'`\s<>]*)?)["'`]""")
_ABS_RE = re.compile(r"""https?://[^\s"'`<>)]+""")
_STATIC = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf",
           ".map", ".mp4", ".webp")


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "GET"),
                               "inputs": []})
        elif tag in ("input", "select", "textarea") and self.forms:
            self.forms[-1]["inputs"].append(a.get("name", ""))


class HuntSession:
    """All state behind the MCP tools (also usable directly in tests)."""

    def __init__(self, scope_file: str, identities_file: str = "", lab_mode: bool = False,
                 budget: int = 800, run_dir: str = "", target: str = ""):
        from hackbot.modes.agent import AgentMode

        self.run_dir = Path(run_dir) if run_dir else Path.cwd() / "hunt-run"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.started = time.time()
        self.target = target
        config = HackBotConfig()
        config.ai = AIConfig(provider="mock", model="mock")
        config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True, auto_confirm=False,
                                   timeout=60)
        config.scope = ScopeConfig(audit_log=False)
        config.validation = ValidationConfig(handoff_dir=str(self.run_dir / "packets"))
        with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
            agent = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
        agent._assessment_id = None
        agent._rag_enabled = False
        agent.scope_policy = ScopePolicy.from_file(scope_file)
        agent.runner.scope_policy = agent.scope_policy
        agent.runner.scope_audit = ScopeAuditLog(self.run_dir / "scope_audit.jsonl")
        agent.corpus.scope_policy = agent.scope_policy
        vault = IdentityVault.from_file(identities_file) if identities_file else \
            IdentityVault({}, max_identities=4)
        agent.identity_vault = agent.runner.identity_vault = agent.corpus.identity_vault = vault
        agent.target = target or (agent.scope_policy.in_scope[0].raw
                                  if agent.scope_policy.in_scope else "")
        self.lab_mode = lab_mode
        if lab_mode:
            agent.runner.on_approve = LabApprover(agent.scope_policy,
                                                  audit_path=self.run_dir / "lab_approvals.jsonl")
        self.agent = agent
        self.calls = self.run_dir / "tool_calls.jsonl"

    # ── bookkeeping ──────────────────────────────────────────────────────
    def _log(self, tool: str, args: Dict[str, Any], result: Any) -> None:
        entry = {"ts": round(time.time() - self.started, 2), "tool": tool, "args": args,
                 "steps": len(self.agent.steps),
                 "result": result if isinstance(result, (str, int, float)) else
                 json.dumps(result, default=str)[:2000]}
        with open(self.calls, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def requests_used(self) -> int:
        return sum(1 for s in self.agent.steps if s.tool_result is not None)

    def _over_budget(self) -> Optional[str]:
        if self.requests_used() >= self.budget:
            return f"request budget exhausted ({self.budget}); record findings and write the report"
        return None

    # ── tools ────────────────────────────────────────────────────────────
    def engagement(self) -> Dict[str, Any]:
        out = {
            "target": self.agent.target,
            "scope": self.agent.scope_policy.summary(),
            "rules": [
                "Only the in-scope hosts/ports may be contacted; everything else is refused.",
                "Use harmless proof markers and synthetic data. No destructive actions, no "
                "mass data extraction, no resource exhaustion, no brute force.",
                "State-changing requests are pre-approved in lab mode; data dumps, secret "
                "reads, credential attacks and heavy load are refused.",
                "A finding is CONFIRMED only through record_finding + the proof gate: cite "
                "verbatim excerpts from steps HackBot executed. Status codes and error "
                "messages alone are not proof.",
            ],
            "lab_mode": self.lab_mode,
            "identities": self.agent.identity_vault.public_view(),
            "budget": {"requests_used": self.requests_used(), "requests_max": self.budget},
        }
        self._log("engagement", {}, "ok")
        return out

    def http_request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                     body: str = "", identity: str = "", follow_redirects: bool = False,
                     purpose: str = "") -> Dict[str, Any]:
        args = {"method": method, "url": url, "identity": identity, "purpose": purpose,
                "body": body[:300]}
        over = self._over_budget()
        if over:
            self._log("http_request", args, over)
            return {"error": over}
        method = (method or "GET").upper()
        argv = ["curl", "-s", "-i", "--max-time", "30", "-X", method]
        if follow_redirects:
            argv += ["-L", "--max-redirs", "3"]
        for k, v in (headers or {}).items():
            argv += ["-H", f"{k}: {v}"]
        if identity and identity != ANONYMOUS:
            try:
                ident = self.agent.identity_vault.get(identity)
            except Exception as exc:  # unknown identity
                return {"error": str(exc)}
            if ident.cookies:
                argv += ["-H", f"Cookie: {{{{cookie:{identity}}}}}"]
            if ident.bearer:
                argv += ["-H", f"Authorization: Bearer {{{{bearer:{identity}}}}}"]
            for h in ident.headers:
                argv += ["-H", f"{h}: {{{{header:{identity}:{h}}}}}"]
        if body:
            argv += ["--data-raw", body]
        argv.append(url)
        step, raw = self.agent.run_recorded(" ".join(shlex.quote(a) for a in argv),
                                            purpose or f"{method} {url}")
        if raw.lstrip().startswith("BLOCKED") or "\nBLOCKED:" in raw:
            res = {"step": step, "blocked": raw.strip()[:500]}
            self._log("http_request", args, res)
            return res
        resp = Response.parse(raw)
        req_headers = dict(headers or {})
        # identity="" lets the corpus attribute manually supplied credentials itself
        self.agent.corpus.add("hunter", method, url, req_headers, body, resp.status,
                              _parse_headers(resp.headers), resp.body, identity=identity)
        learned: List[str] = []
        if identity and identity != ANONYMOUS and 200 <= resp.status < 300:
            # D9: link the identity's numeric id to it when its own response shows both
            learned = self.agent.identity_vault.learn_from_response(identity, resp.body)
        res = {"step": step, "status": resp.status, "headers": resp.headers[:3000],
               "body": resp.body[:BODY_LIMIT], "body_truncated": len(resp.body) > BODY_LIMIT,
               "requests_left": self.budget - self.requests_used()}
        if learned:
            res["learned_markers"] = learned
        self._log("http_request", args, {"step": step, "status": resp.status,
                                         "len": len(resp.body)})
        return res

    def extract_links(self, step: int) -> Dict[str, Any]:
        st = next((s for s in self.agent.steps if s.step_num == step and s.tool_result), None)
        if st is None:
            return {"error": f"no captured step {step}"}
        url = next((t for t in shlex.split(st.tool_result.command) if "://" in t), "")
        body = Response.parse(f"{st.tool_result.stdout}").body
        parser = _Links()
        try:
            parser.feed(body)
        except Exception:
            pass
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(url)) if url else ""
        paths = sorted({m for m in _PATH_RE.findall(body)
                        if len(m) > 1 and not m.lower().endswith(_STATIC) and "//" not in m})
        absolute = sorted({u.rstrip(".,;") for u in _ABS_RE.findall(body)})
        res = {
            "links": sorted({urljoin(url, h) for h in parser.links})[:300],
            "scripts": sorted({urljoin(url, s) for s in parser.scripts})[:100],
            "forms": parser.forms[:50],
            "path_strings": paths[:500],
            "absolute_urls": [u for u in absolute if self.agent.scope_policy.check_raw_target(u)[0]
                              or u.startswith(origin)][:200],
        }
        self._log("extract_links", {"step": step},
                  {k: len(v) for k, v in res.items() if isinstance(v, list)})
        return res

    def register_identity(self, name: str, role: str = "user", bearer: str = "",
                          cookies: Optional[Dict[str, str]] = None,
                          markers: Optional[List[str]] = None,
                          owned: Optional[Dict[str, List[str]]] = None,
                          tenant: str = "") -> Dict[str, Any]:
        vault = self.agent.identity_vault
        if name in vault.identities and name != ANONYMOUS:
            ident = vault.get(name)
            ident.role, ident.tenant = role or ident.role, tenant or ident.tenant
            ident.bearer = bearer or ident.bearer
            ident.cookies.update(cookies or {})
            ident.markers = list(dict.fromkeys(ident.markers + list(markers or [])))
            for k, ids in (owned or {}).items():
                for i in ids:
                    vault.add_owned(name, k, str(i))
        else:
            if len([n for n in vault.identities if n != ANONYMOUS]) >= vault.max_identities:
                return {"error": f"identity limit {vault.max_identities} reached"}
            vault.identities[name] = Identity(name=name, role=role, tenant=tenant, bearer=bearer,
                                              cookies=dict(cookies or {}),
                                              markers=list(markers or []),
                                              owned={k: [str(i) for i in v]
                                                     for k, v in (owned or {}).items()})
        vault._rebuild_secrets()
        self._log("register_identity", {"name": name, "role": role}, "ok")
        return {"ok": True, "identities": vault.public_view()}

    def record_finding(self, **fields: Any) -> Dict[str, Any]:
        msg = self.agent._record_finding({"action": "finding", **fields})
        f = getattr(self.agent, "last_finding", None) or self.agent.findings[-1]
        res = {"message": msg, "index": self.agent.findings.index(f),
               "status": "CONFIRMED" if f.confirmed else "UNVERIFIED LEAD",
               "missing": f.proof.get("missing", []),
               "prevalidation": f.validation.get("label")}
        self._log("record_finding", {"title": fields.get("title")}, res["status"])
        return res

    def assess_finding(self, index: int, assessment: str, reason: str) -> Dict[str, Any]:
        allowed = ("false_positive", "expected_behavior", "inconclusive")
        if assessment not in allowed:
            return {"error": f"assessment must be one of {allowed}"}
        f = self.agent.findings[index]
        f.fp_triage["hunter_assessment"] = {"assessment": assessment, "reason": reason}
        self._log("assess_finding", {"index": index, "assessment": assessment}, "ok")
        return {"ok": True}

    def findings(self) -> List[Dict[str, Any]]:
        return [{"index": i, "title": f.title, "status": classify(f), "severity": f.severity.value,
                 "missing": f.proof.get("missing", []),
                 "prevalidation": f.validation.get("label")}
                for i, f in enumerate(self.agent.findings)]

    def write_report(self, summary: str = "") -> Dict[str, Any]:
        packets = [str(self.agent.export_handoff(i)) for i in range(len(self.agent.findings))]
        report = self.run_dir / "report.md"
        lines = [f"# HUNTIX hunt report — {self.agent.target}", "",
                 f"requests used: {self.requests_used()} / {self.budget} · "
                 f"elapsed: {time.time() - self.started:.0f}s", "", "## Hunter summary", "",
                 summary or "_none_", "", "## Findings", ""]
        for i, f in enumerate(self.agent.findings):
            lines += [f"### {i + 1}. [{classify(f)}] {f.title}",
                      f"- class: {f.vuln_class or '-'} · boundary: "
                      f"{f.boundary_type or f.boundary or '-'}",
                      f"- impact: {f.impact or '-'}",
                      f"- pre-validation: {f.validation.get('label', '-')}"]
            ha = f.fp_triage.get("hunter_assessment")
            if ha:
                lines.append(f"- hunter assessment: {ha['assessment']} — {ha['reason']}")
            for m in f.proof.get("missing", []):
                lines.append(f"- missing: {m}")
            lines.append("")
        report.write_text("\n".join(lines))
        self._log("write_report", {}, str(report))
        return {"report": str(report), "packets": packets}


def classify(f: Any) -> str:
    if f.dismissed:
        return "FALSE POSITIVE"
    if f.confirmed:
        return "CONFIRMED"
    ha = (f.fp_triage.get("hunter_assessment") or {}).get("assessment")
    return {"false_positive": "FALSE POSITIVE", "expected_behavior": "EXPECTED BEHAVIOR",
            "inconclusive": "INCONCLUSIVE"}.get(ha, "UNVERIFIED LEAD")


def _parse_headers(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines()[1:]:
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def build_server(session: HuntSession) -> Any:
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        name="huntix",
        instructions=("HUNTIX evidence-driven hunting tools. Every request is scope-checked, "
                      "gated and recorded. Start with `engagement`."),
    )

    @server.tool(description="Target, scope, rules of engagement, test identities and budget.")
    def engagement() -> Dict[str, Any]:
        return session.engagement()

    @server.tool(description="Send one HTTP request (scope-checked, gated, recorded as a step). "
                             "identity = a registered test identity name to authenticate as.")
    def http_request(method: str, url: str, headers: Optional[Dict[str, str]] = None,
                     body: str = "", identity: str = "", follow_redirects: bool = False,
                     purpose: str = "") -> Dict[str, Any]:
        return session.http_request(method, url, headers, body, identity, follow_redirects,
                                    purpose)

    @server.tool(description="Links, forms, scripts and path-like strings found in a captured "
                             "step's response body (use on HTML pages and JS bundles).")
    def extract_links(step: int) -> Dict[str, Any]:
        return session.extract_links(step)

    @server.tool(description="Register/update a test identity (credentials are hidden from "
                             "later output; markers = how it shows up in responses — include "
                             "its email AND its user id; owned = {object_type: [ids]} it owns).")
    def register_identity(name: str, role: str = "user", bearer: str = "",
                          cookies: Optional[Dict[str, str]] = None,
                          markers: Optional[List[str]] = None,
                          owned: Optional[Dict[str, List[str]]] = None,
                          tenant: str = "") -> Dict[str, Any]:
        return session.register_identity(name, role, bearer, cookies, markers, owned, tenant)

    @server.tool(description="Endpoints observed so far (method, template, identities, statuses).")
    def corpus_endpoints() -> List[Dict[str, Any]]:
        return session.agent.corpus.endpoints()

    @server.tool(description="Object-ID parameters observed so far with their ledger owners.")
    def corpus_id_candidates() -> List[Dict[str, Any]]:
        return session.agent.corpus.id_candidates()

    @server.tool(description="Replay a corpus exchange as other identities (BOLA/BFLA diff).")
    def authz_diff(exchange_id: int, identities: Optional[List[str]] = None) -> str:
        return session.agent._process_authz_diff_action(
            {"exchange_id": exchange_id, "identities": identities})

    @server.tool(description="Ownership-aware object-ID substitution across the corpus.")
    def bola_scan(exchange_id: Optional[int] = None) -> str:
        return session.agent._process_bola_action({"exchange_id": exchange_id})

    @server.tool(description="Function inventory + role x function matrix.")
    def bfla_scan() -> str:
        return session.agent._process_bfla_action({})

    @server.tool(description="Submit a finding to the proof gate. evidence_refs = "
                             "[{step, excerpt (verbatim from that step), supports}].")
    def record_finding(title: str, severity: str, vuln_class: str, behavior: str,
                       boundary: str, impact: str, evidence_refs: List[Dict[str, Any]],
                       reproduction: str = "", asset: str = "", privileges_required: str = "",
                       attacker_identity: str = "", victim_identity: str = "",
                       victim_identifier: str = "", description: str = "") -> Dict[str, Any]:
        return session.record_finding(
            title=title, severity=severity, vuln_class=vuln_class, behavior=behavior,
            boundary=boundary, impact=impact, evidence_refs=evidence_refs,
            reproduction=reproduction, asset=asset, privileges_required=privileges_required,
            attacker_identity=attacker_identity, victim_identity=victim_identity,
            victim_identifier=victim_identifier, description=description)

    @server.tool(description="Mark a lead as false_positive, expected_behavior or inconclusive, "
                             "with the reason.")
    def assess_finding(index: int, assessment: str, reason: str) -> Dict[str, Any]:
        return session.assess_finding(index, assessment, reason)

    @server.tool(description="All findings with status and missing proof.")
    def findings() -> List[Dict[str, Any]]:
        return session.findings()

    @server.tool(description="Write the final report and evidence packets. Call once at the end.")
    def write_report(summary: str = "") -> Dict[str, Any]:
        return session.write_report(summary)

    return server


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scope", required=True)
    ap.add_argument("--identities", default="")
    ap.add_argument("--lab-mode", action="store_true")
    ap.add_argument("--budget", type=int, default=800)
    ap.add_argument("--run-dir", default="")
    ap.add_argument("--target", default="")
    a = ap.parse_args(argv)
    session = HuntSession(a.scope, a.identities, a.lab_mode, a.budget, a.run_dir, a.target)
    build_server(session).run("stdio")


if __name__ == "__main__":
    main()
