"""End-to-end tests for differential authorization replay (BOLA / BFLA engine)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.authz_diff import Response, normalize, similarity
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityVault
from hackbot.core.scope import ScopePolicy

A_SESSION = "sess-" + "a" * 24
B_SESSION = "sess-" + "b" * 24
ADMIN_TOKEN = "tok-" + "c" * 30

ORDER_B = '{"id": 5002, "owner": "hunter-b@example.com", "total": 42}'


def http(status, body, extra=""):
    reason = {200: "OK", 302: "Found", 403: "Forbidden"}.get(status, "X")
    return f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}\r\n{body}"


class FakeServer:
    """Answers curl argv like a target would, keyed on which credential is sent."""

    def __init__(self, routes):
        self.routes = routes  # fn(argv_text) -> raw response
        self.calls = []

    def popen(self, argv, **kwargs):
        server = self
        text = " ".join(argv)
        server.calls.append(text)

        class P:
            returncode = 0
            stdout = None

            def communicate(self, input=None, timeout=None):
                return server.routes(text), ""
        return P()


def vulnerable(text):
    if A_SESSION in text or B_SESSION in text or ADMIN_TOKEN in text or "Cookie" not in text:
        if "/orders/5002" in text and "Cookie" not in text and ADMIN_TOKEN not in text:
            return http(403, '{"error": "forbidden"}')  # anonymous denied
        return http(200, ORDER_B)
    return http(403, "{}")


def secure(text):
    if B_SESSION in text:
        return http(200, ORDER_B)
    return http(403, '{"error": "forbidden"}')


@pytest.fixture
def vault():
    return IdentityVault.from_dict({"identities": {
        "user-a": {"role": "user", "cookies": {"session": A_SESSION},
                   "markers": ["hunter-a@example.com"], "owned": {"order": ["5001"]}},
        "user-b": {"role": "user", "cookies": {"session": B_SESSION},
                   "markers": ["hunter-b@example.com"], "owned": {"order": ["5002"]}},
        "admin": {"role": "admin", "bearer": ADMIN_TOKEN, "markers": ["admin@example.com"]},
    }})


@pytest.fixture
def agent(vault):
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a._assessment_id = None
    a._rag_enabled = False
    a.target = "api.example.com"
    a.scope_policy = ScopePolicy(in_scope=["api.example.com"])
    a.runner.scope_policy = a.scope_policy
    a.identity_vault = vault
    a.runner.identity_vault = vault
    a.corpus.identity_vault = vault
    a.corpus.scope_policy = a.scope_policy
    return a


def _serve(monkeypatch, routes):
    server = FakeServer(routes)
    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", server.popen)
    return server


def _b_order(agent, method="GET", url="https://api.example.com/v1/orders/5002", body=""):
    return agent.corpus.add("har", method, url, {"Cookie": f"session={B_SESSION}",
                                                 "Accept": "application/json"},
                            body, 200, {}, ORDER_B)


class TestEndToEnd:
    def test_bola_found_and_confirmed(self, agent, monkeypatch):
        server = _serve(monkeypatch, vulnerable)
        ex = _b_order(agent)
        out = agent.authz_diff(ex.id, ["user-a", "anonymous"])
        verdicts = {v["identity"]: v["verdict"] for v in out["variants"]}
        assert verdicts == {"user-a": "exposed", "anonymous": "denied"}
        assert len(agent.findings) == 1
        f = agent.findings[0]
        assert f.confirmed, f.proof
        assert f.vuln_class == "idor"
        assert f.attacker_identity == "user-a" and f.victim_identity == "user-b"
        assert f.validation["verdict"] == "ready_for_validator", f.validation
        # credentials only ever existed inside argv
        assert any(A_SESSION in c for c in server.calls)
        dump = json.dumps([f.to_dict()] + [s.tool_result.to_dict() for s in agent.steps
                                            if s.tool_result is not None])
        for secret in (A_SESSION, B_SESSION, ADMIN_TOKEN):
            assert secret not in dump

    def test_secure_endpoint_no_finding(self, agent, monkeypatch):
        _serve(monkeypatch, secure)
        out = agent.authz_diff(_b_order(agent).id)
        assert {v["verdict"] for v in out["variants"]} == {"denied"}
        assert agent.findings == []

    def test_bfla_classification(self, agent, monkeypatch):
        _serve(monkeypatch, lambda t: http(200, ORDER_B))
        ex = agent.corpus.add("har", "GET", "https://api.example.com/admin/orders/5002",
                              {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 200, {},
                              '{"owner": "admin@example.com"}')
        agent.identity_vault.get("admin").markers.append("hunter-b@example.com")
        out = agent.authz_diff(ex.id, ["user-a"])
        assert out["variants"][0]["verdict"] == "exposed"
        assert agent.findings[0].vuln_class == "bfla"

    def test_anonymous_access_is_auth_bypass(self, agent, monkeypatch):
        _serve(monkeypatch, lambda t: http(200, ORDER_B))
        agent.authz_diff(_b_order(agent).id, ["anonymous"])
        assert agent.findings[0].vuln_class == "auth bypass"
        assert agent.findings[0].privileges_required == "none"

    def test_no_marker_is_only_a_lead(self, agent, monkeypatch):
        _serve(monkeypatch, lambda t: http(200, '{"status": "ok", "items": []}'))
        out = agent.authz_diff(_b_order(agent).id, ["user-a"])
        assert out["variants"][0]["verdict"] == "same_as_baseline"
        assert "markers not in the baseline" in out["baseline"]["detail"]
        assert agent.findings == []

    def test_attackers_own_marker_does_not_count(self, agent, monkeypatch):
        _serve(monkeypatch, lambda t: http(200, '{"me": "hunter-a@example.com", '
                                                '"note": "hunter-b@example.com"}'
                                           if A_SESSION in t else ORDER_B))
        agent.identity_vault.get("user-b").markers.insert(0, "hunter-a@example.com")
        out = agent.authz_diff(_b_order(agent).id, ["user-a"])
        assert out["variants"][0]["owner_marker"] == "hunter-b@example.com"

    def test_login_redirect_is_denied(self, agent, monkeypatch):
        _serve(monkeypatch, lambda t: http(200, ORDER_B) if B_SESSION in t
               else http(302, "", "Location: /login\r\n"))
        out = agent.authz_diff(_b_order(agent).id, ["user-a"])
        assert out["variants"][0]["verdict"] == "denied"


class TestSafety:
    def test_unattributed_exchange_refused(self, agent):
        ex = agent.corpus.add("har", "GET", "https://api.example.com/v1/orders/5002",
                              {"Cookie": "session=stranger"})
        assert "not attributed" in agent.authz_diff(ex.id)["refused"]

    def test_state_change_on_foreign_object_refused(self, agent, monkeypatch):
        server = _serve(monkeypatch, vulnerable)
        ex = _b_order(agent, "DELETE", "https://api.example.com/v1/orders/9999")
        out = agent.authz_diff(ex.id, ["user-a"])
        assert "ownership ledger" in out["refused"]
        assert server.calls == []

    def test_state_change_on_ledger_object_still_needs_a_human(self, agent, monkeypatch):
        server = _serve(monkeypatch, vulnerable)
        ex = _b_order(agent, "DELETE", "https://api.example.com/v1/orders/5002")
        out = agent.authz_diff(ex.id, ["user-a"])  # no on_approve wired → denied
        assert out["refused"] == "baseline request was blocked"
        assert "NOT APPROVED" in out["baseline"]["detail"]
        assert server.calls == []

    def test_out_of_scope_exchange_never_sent(self, agent, monkeypatch):
        server = _serve(monkeypatch, vulnerable)
        agent.corpus.scope_policy = None  # imported before scope was tightened
        ex = agent.corpus.add("har", "GET", "https://evil.org/v1/orders/5002",
                              {"Cookie": f"session={B_SESSION}"})
        out = agent.authz_diff(ex.id, ["user-a"])
        assert "OUT OF SCOPE" in out["baseline"]["detail"]
        assert server.calls == []

    def test_requires_identities(self, agent):
        agent.identity_vault = None
        assert "identities" in agent.authz_diff(1)["refused"]


def test_agent_action_summary(agent, monkeypatch):
    _serve(monkeypatch, vulnerable)
    ex = _b_order(agent)
    text = agent._process_authz_diff_action({"exchange_id": ex.id, "identities": ["user-a"]})
    assert "as user-a: exposed" in text and "[Proof gate]" in text


def test_response_parse_last_block():
    raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 200\r\nx: y\r\n\r\n{\"a\": 1}"
    r = Response.parse(raw)
    assert r.status == 200 and r.body == '{"a": 1}'


def test_similarity_ignores_dynamic_values():
    a = '{"id": 5, "at": "2026-10-19T10:00:01Z", "nonce": "' + "f" * 32 + '"}'
    b = '{"id": 5, "at": "2026-10-19T11:22:33Z", "nonce": "' + "0" * 32 + '"}'
    assert normalize(a) == normalize(b)
    assert similarity(a, b) == 1.0


def test_diff_and_bola_same_bug_is_one_finding(agent, monkeypatch):
    _serve(monkeypatch, vulnerable)
    agent.identity_vault.get("user-a").owned = {"order": ["5001"]}
    agent.identity_vault.get("user-b").owned = {"order": ["5002"]}
    agent.corpus.add("har", "GET", "https://api.example.com/v1/orders/5001",
                     {"Cookie": f"session={A_SESSION}"}, "", 200, {}, "{}")
    ex_b = _b_order(agent)
    agent.authz_diff(ex_b.id, ["user-a"])
    agent.bola_scan()
    idor = [f for f in agent.findings if f.vuln_class == "idor"]
    assert len(idor) == 1
    assert len(idor[0].evidence_refs) >= 2  # evidence from both engines merged
    assert idor[0].attacker_identity == "user-a"  # first write-up is kept
    assert idor[0].confirmed
