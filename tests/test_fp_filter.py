"""Tests for the false-positive classifier and human review workflow."""

from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.engine import AIEngine
from hackbot.core.fp_filter import FalsePositiveClassifier
from hackbot.core.runner import ToolResult
from hackbot.core.scope import ScopePolicy
from hackbot.reporting import calculate_security_posture


def _classify(title, excerpt, output="", cls="", command="curl -s https://a.example.com/x",
              **extra):
    finding = {"raw_title": title, "vuln_class": cls,
               "proof": {"verified_refs": [{"excerpt": excerpt, "step": 1}]}, **extra}
    return FalsePositiveClassifier().classify(
        finding, {1: {"command": command, "output": output or excerpt}})


def _codes(result):
    return [s["code"] for s in result["signals"]]


class TestSignals:
    def test_waf_block_page(self):
        r = _classify("SQL injection in search", "' OR 1=1--",
                      "HTTP/1.1 403 Forbidden\ncf-ray: 8a1\n"
                      "<title>Attention Required! | Cloudflare</title>")
        assert "WAF_BLOCK_PAGE" in _codes(r)
        assert r["label"] == "likely_false_positive"

    def test_soft_404(self):
        r = _classify("Exposed backup file /db.sql", "<h1>Page not found</h1>",
                      "HTTP/1.1 200 OK\n<h1>Page not found</h1>")
        assert "SOFT_404" in _codes(r)

    def test_login_redirect_is_not_auth_bypass(self):
        r = _classify("Auth bypass on /admin/users", "HTTP/1.1 302 Found",
                      "HTTP/1.1 302 Found\nLocation: /login?next=/admin/users")
        assert "LOGIN_REDIRECT" in _codes(r)

    def test_spa_shell_is_not_admin_access(self):
        out = 'HTTP/1.1 200 OK\n<html><body><div id="root"></div><script src="/main.js">'
        r = _classify("Auth bypass: /admin panel accessible", '<div id="root"></div>', out)
        assert "SPA_SHELL_ONLY" in _codes(r)

    def test_spa_shell_with_api_data_not_flagged(self):
        out = '<div id="root"></div>\n{"users": [{"email": "a@b.c"}]}'
        r = _classify("Auth bypass on /admin", '{"users": [{"email": "a@b.c"}]}', out)
        assert "SPA_SHELL_ONLY" not in _codes(r)

    def test_encoded_xss_reflection(self):
        r = _classify("Reflected XSS in q", "&lt;script&gt;alert(1)&lt;/script&gt;")
        assert "ENCODED_REFLECTION" in _codes(r)

    def test_raw_xss_reflection_not_flagged(self):
        r = _classify("Reflected XSS in q", "<script>alert(document.domain)</script>")
        assert "ENCODED_REFLECTION" not in _codes(r)

    @pytest.mark.parametrize("key", [
        "pk_live_51HxYzAbCdEfGhIjKl",
        "AIza" + "Sy" + "A" * 33,  # built at runtime: fake, keeps secret scanners quiet
        "https://0123456789abcdef0123456789abcdef@o12345.ingest.sentry.io/678",
    ])
    def test_publishable_keys(self, key):
        r = _classify("API key disclosure in main.js", f'apiKey: "{key}"')
        assert "PUBLISHABLE_KEY" in _codes(r)

    def test_real_secret_not_flagged_as_publishable(self):
        r = _classify("AWS key disclosure", "AKIAIOSFODNN7EXAMPLE pk_live_51HxYzAbCdEfGhIjKl")
        assert "PUBLISHABLE_KEY" not in _codes(r)

    def test_scanner_only_evidence(self):
        r = _classify("Exposed .git directory", "[git-config] [http] [medium]",
                      command="nuclei -u https://a.example.com -t exposures/")
        assert "SCANNER_ONLY" in _codes(r)
        assert r["label"] == "needs_review"  # medium confidence only

    def test_self_target(self):
        r = _classify("IDOR on /orders", '"owner": "user-a"',
                      attacker_identity="user-a", victim_identity="user-a")
        assert "SELF_TARGET" in _codes(r)

    def test_status_only(self):
        r = _classify("BOLA on /v1/invoices/7", "HTTP/1.1 200 OK")
        assert "STATUS_CODE_ONLY" in _codes(r)

    def test_default_page(self):
        r = _classify("Exposed server", "Welcome to nginx!")
        assert "DEFAULT_PAGE" in _codes(r)

    def test_clean_idor_has_no_signal(self):
        r = _classify("IDOR on /v1/orders", '{"id": 1002, "email": "victim@example.com"}',
                      attacker_identity="user-a", victim_identity="user-b")
        assert r == {"label": "no_fp_signal", "signals": []}


# ── Agent workflow ───────────────────────────────────────────────────────────

WAF_OUT = ('HTTP/1.1 403 Forbidden\ncf-ray: 8a1\n<title>Attention Required! | Cloudflare</title>\n'
           'admin dashboard data id=4411')


@pytest.fixture
def agent(tmp_path):
    from hackbot.core.vulndb import VulnDB
    from hackbot.modes.agent import AgentMode, AgentStep

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a.vulndb = VulnDB(db_path=tmp_path / "v.db")
    a._assessment_id = a.vulndb.create_assessment(target="a.example.com")
    a._rag_enabled = False
    a.target = "a.example.com"
    a.scope_policy = ScopePolicy(in_scope=["*.example.com"])
    res = ToolResult(tool="curl", command="curl -s https://a.example.com/admin?x=1",
                     stdout=WAF_OUT, stderr="", return_code=0, duration=0.1, success=True)
    a.steps.append(AgentStep(step_num=1, action="execute", description="", tool_result=res))
    return a


ACTION = {
    "action": "finding", "title": "Auth bypass on /admin", "severity": "High",
    "behavior": "unauthenticated GET /admin?x=1 returned admin dashboard data",
    "boundary": "authentication on the admin interface",
    "impact": "an unauthenticated user read admin dashboard record id=4411",
    "evidence_refs": [{"step": 1, "excerpt": "admin dashboard data id=4411"}],
    "asset": "https://a.example.com/admin", "privileges_required": "none",
    "attacker_identity": "anonymous", "victim_identity": "admin",
    "victim_identifier": "id=4411",
}


class TestReviewWorkflow:
    def test_flagged_but_never_removed(self, agent):
        msg = agent._record_finding(dict(ACTION))
        f = agent.findings[0]
        assert f.confirmed  # the proof gate is unaffected by the FP screen
        assert f.fp_triage["label"] == "likely_false_positive"
        assert "[FP screen]" in msg and "WAF_BLOCK_PAGE" in msg
        assert len(agent.findings) == 1

    def test_unreviewed_fp_blocks_ready_verdict(self, agent):
        agent._record_finding(dict(ACTION))
        assert agent.findings[0].validation["verdict"] == "review_required"

    def test_human_valid_review_unblocks(self, agent):
        agent._record_finding(dict(ACTION))
        f = agent.review_finding(0, "valid", "WAF page is a 403 wrapper; data still leaked")
        assert f.validation["verdict"] == "ready_for_validator"
        assert not f.dismissed

    def test_human_false_positive_dismisses_and_keeps_record(self, agent):
        agent._record_finding(dict(ACTION))
        f = agent.review_finding(0, "false_positive", "Cloudflare challenge page")
        assert f.dismissed
        assert len(agent.findings) == 1
        d = f.to_dict()
        assert d["title"].startswith("[DISMISSED — FALSE POSITIVE]")
        assert f.validation["verdict"] == "kill"
        assert calculate_security_posture([d])["counts"]["High"] == 0
        rec = agent.vulndb.get_finding(f.db_id)
        assert rec.status == "false_positive"
        text = agent.get_findings_summary()
        assert "Dismissed (human review): 1" in text
        assert "Cloudflare challenge page" in text

    def test_reverting_review_reopens_in_db(self, agent):
        agent._record_finding(dict(ACTION))
        agent.review_finding(0, "false_positive", "oops")
        f = agent.review_finding(0, "valid", "re-checked")
        assert not f.dismissed
        assert agent.vulndb.get_finding(f.db_id).status == "open"

    def test_review_survives_re_evaluation(self, agent):
        agent._record_finding(dict(ACTION))
        agent.review_finding(0, "valid", "checked")
        agent._record_finding(dict(ACTION))  # resubmission re-runs every gate
        assert agent.findings[0].fp_triage["review"]["decision"] == "valid"

    def test_invalid_decision_rejected(self, agent):
        agent._record_finding(dict(ACTION))
        with pytest.raises(ValueError):
            agent.review_finding(0, "delete")

    def test_gui_review_endpoint(self, agent):
        from hackbot.gui import app as gui

        agent._record_finding(dict(ACTION))
        gui._state["agent"] = agent
        client = gui.app.test_client()
        bad = client.post("/api/agent/findings/0/review", json={"decision": "delete"})
        assert bad.status_code == 400
        ok = client.post("/api/agent/findings/0/review",
                         json={"decision": "false_positive", "note": "WAF"})
        assert ok.status_code == 200
        assert ok.get_json()["finding"]["dismissed"] is True
        assert client.post("/api/agent/findings/9/review", json={}).status_code == 404
