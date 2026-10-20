"""Tests for lab mode (loopback-only auto-approval) and the MCP hunt session."""

import json

import pytest

from hackbot.core.lab_mode import LabApprover, is_loopback_policy
from hackbot.core.scope import ScopePolicy
from hackbot.mcp_server import HuntSession, build_server

TOKEN = "jwt-" + "q" * 40


@pytest.mark.parametrize("rules,ok", [
    (["http://127.0.0.1:3000"], True),
    (["localhost:8888", "http://[::1]:3000"], True),
    (["127.0.0.0/8"], True),
    (["http://127.0.0.1:3000", "api.example.com"], False),
    (["*.lab.test"], False),
    (["10.0.0.0/8"], False),
    ([], False),
])
def test_loopback_policy(rules, ok):
    assert is_loopback_policy(ScopePolicy(in_scope=rules)) is ok


def test_lab_approver_refuses_non_loopback_scope():
    with pytest.raises(ValueError):
        LabApprover(ScopePolicy(in_scope=["api.example.com"]))


def test_lab_approver_categories(tmp_path):
    ap = LabApprover(ScopePolicy(in_scope=["http://127.0.0.1:3000"]),
                     audit_path=tmp_path / "a.jsonl")
    assert ap("curl -X POST ...", "IMPACT-ESCALATION [state_change]: POST request ...")
    assert not ap("curl ...", "IMPACT-ESCALATION [sensitive_data]: request reads password hashes")
    assert not ap("curl ...", "IMPACT-ESCALATION [data_extraction]: sqlmap --dump")
    assert not ap("httpx", "SCOPE UNVERIFIED: no target")
    lines = [json.loads(x) for x in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert [x["approved"] for x in lines] == [True, False, False, False]


# ── hunt session ─────────────────────────────────────────────────────────────


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("in_scope: ['http://127.0.0.1:3000']\n"
                 "out_of_scope: ['http://127.0.0.1:3000/api/Challenges']\n")
    return f


class FakeLab:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        text = " ".join(argv)
        self.calls.append(text)
        lab = self

        class P:
            returncode = 0
            stdout = None

            def communicate(self, input=None, timeout=None):
                return lab.respond(text), ""
        return P()

    def respond(self, text):
        if "/rest/user/login" in text:
            return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                    + json.dumps({"authentication": {"token": TOKEN, "umail": "h1@lab.test"}}))
        if TOKEN in text and "/rest/basket/2" in text:
            return ('HTTP/1.1 200 OK\r\n\r\n{"data": {"id": 2, "UserId": 2, '
                    '"owner": "h2@lab.test"}}')
        if "/main.js" in text:
            return 'HTTP/1.1 200 OK\r\n\r\nfetch("/rest/basket/"+id); x="/api/Users"; "/x.png"'
        return ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><a href="/about">a</a>'
                '<script src="/main.js"></script><form action="/search" method="get">'
                '<input name="q"></form></html>')


@pytest.fixture
def lab(monkeypatch):
    fake = FakeLab()
    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", fake)
    return fake


def _session(scope_file, tmp_path, **kw):
    return HuntSession(str(scope_file), run_dir=str(tmp_path / "run"), lab_mode=True, **kw)


class TestHuntSession:
    def test_engagement_has_no_secrets_and_rules(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        e = s.engagement()
        assert "127.0.0.1:3000" in e["scope"] and e["lab_mode"] is True
        assert e["budget"]["requests_max"] == 800

    def test_out_of_scope_and_excluded_paths_refused(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        assert "OUT OF SCOPE" in s.http_request("GET", "http://127.0.0.1:3001/")["blocked"]
        assert "OUT OF SCOPE" in s.http_request(
            "GET", "http://127.0.0.1:3000/API/challenges")["blocked"]
        assert "OUT OF SCOPE" in s.http_request("GET", "https://example.org/")["blocked"]
        assert lab.calls == []

    def test_post_auto_approved_in_lab_mode_and_recorded(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        r = s.http_request("POST", "http://127.0.0.1:3000/rest/user/login",
                           {"Content-Type": "application/json"},
                           '{"email": "h1@lab.test", "password": "x"}')
        assert r["status"] == 200 and TOKEN in r["body"]
        approvals = (tmp_path / "run" / "lab_approvals.jsonl").read_text()
        assert '"state_change"' in approvals

    def test_identity_placeholders_and_redaction(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        s.register_identity("h1", bearer=TOKEN, markers=["h1@lab.test"], owned={"basket": ["1"]})
        r = s.http_request("GET", "http://127.0.0.1:3000/rest/basket/2", identity="h1")
        assert r["status"] == 200 and "h2@lab.test" in r["body"]
        assert any(TOKEN in c for c in lab.calls)
        assert TOKEN not in json.dumps(s.engagement())
        log = (tmp_path / "run" / "tool_calls.jsonl").read_text()
        assert TOKEN not in log

    def test_extract_links(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        page = s.http_request("GET", "http://127.0.0.1:3000/")
        links = s.extract_links(page["step"])
        assert "http://127.0.0.1:3000/main.js" in links["scripts"]
        assert links["forms"][0]["inputs"] == ["q"]
        js = s.http_request("GET", "http://127.0.0.1:3000/main.js")
        paths = s.extract_links(js["step"])["path_strings"]
        assert "/rest/basket/" in paths and "/api/Users" in paths and "/x.png" not in paths

    def test_budget(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path, budget=2)
        s.http_request("GET", "http://127.0.0.1:3000/")
        s.http_request("GET", "http://127.0.0.1:3000/")
        assert "budget exhausted" in s.http_request("GET", "http://127.0.0.1:3000/")["error"]
        assert len(lab.calls) == 2

    def test_record_finding_and_classification(self, scope_file, tmp_path, lab):
        s = _session(scope_file, tmp_path)
        s.register_identity("h1", bearer=TOKEN, markers=["h1@lab.test"])
        s.register_identity("h2", markers=["h2@lab.test"])
        r = s.http_request("GET", "http://127.0.0.1:3000/rest/basket/2", identity="h1")
        res = s.record_finding(
            title="IDOR on basket", severity="Medium", vuln_class="idor",
            behavior="h1's token reading /rest/basket/2 returns h2's basket",
            boundary="object-level authorization between two accounts",
            impact="h1 read h2's basket contents including h2's email",
            evidence_refs=[{"step": r["step"], "excerpt": '"owner": "h2@lab.test"'}],
            attacker_identity="h1", victim_identity="h2", victim_identifier="h2@lab.test",
            asset="http://127.0.0.1:3000/rest/basket/2", privileges_required="user")
        assert res["status"] == "CONFIRMED", res
        lead = s.record_finding(title="Maybe SQLi", severity="High", vuln_class="sqli",
                                behavior="500 on quote", boundary="query", impact="",
                                evidence_refs=[])
        assert lead["status"] == "UNVERIFIED LEAD"
        s.assess_finding(lead["index"], "inconclusive", "generic 500, no oracle")
        statuses = [f["status"] for f in s.findings()]
        assert statuses == ["CONFIRMED", "INCONCLUSIVE"]
        out = s.write_report("done")
        assert (tmp_path / "run" / "report.md").read_text().count("[CONFIRMED]") == 1
        assert len(out["packets"]) == 2

    def test_server_registers_tools(self, scope_file, tmp_path, lab):
        import asyncio

        server = build_server(_session(scope_file, tmp_path))
        names = {t.name for t in asyncio.run(server.list_tools())}
        assert {"engagement", "http_request", "extract_links", "register_identity",
                "record_finding", "bola_scan", "bfla_scan", "write_report"} <= names
