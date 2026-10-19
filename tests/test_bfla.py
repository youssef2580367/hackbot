"""Tests for BFLA: function inventory, OPTIONS sibling discovery, role × function matrix."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.bfla import BflaTester, render_matrix
from hackbot.core.corpus import Corpus
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityVault
from hackbot.core.scope import ScopePolicy

A_SESSION = "sess-" + "a" * 24
B_SESSION = "sess-" + "b" * 24
ADMIN_TOKEN = "tok-" + "c" * 30

USERS = json.dumps({"users": [{"email": "hunter-a@example.com"},
                              {"email": "hunter-b@example.com"}]})


def http(status, body="", headers=""):
    return f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{headers}\r\n{body}"


@pytest.fixture
def vault():
    return IdentityVault.from_dict({"identities": {
        "user-a": {"role": "user", "cookies": {"session": A_SESSION},
                   "markers": ["hunter-a@example.com"]},
        "user-b": {"role": "user", "cookies": {"session": B_SESSION},
                   "markers": ["hunter-b@example.com"]},
        "admin": {"role": "admin", "bearer": ADMIN_TOKEN, "markers": ["admin@example.com"]},
    }})


def _corpus(vault):
    c = Corpus(scope_policy=ScopePolicy(in_scope=["api.example.com"]), identity_vault=vault)
    c.add("har", "GET", "https://api.example.com/v1/admin/users",
          {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 200, {}, USERS)
    c.add("har", "GET", "https://api.example.com/v1/reports/7",
          {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 200, {}, "{}")
    c.add("har", "GET", "https://api.example.com/v1/me",
          {"Cookie": f"session={A_SESSION}"}, "", 200, {}, "{}")
    c.add("har", "GET", "https://api.example.com/v1/me",
          {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 200, {}, "{}")
    c.add("har", "GET", "https://api.example.com/v1/settings",
          {"Cookie": f"session={A_SESSION}"}, "", 403, {}, "{}")
    c.add("har", "GET", "https://api.example.com/v1/settings",
          {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 200, {}, "{}")
    return c


class TestVaultRanks:
    def test_defaults_and_override(self, vault):
        assert vault.rank("anonymous") == 0
        assert vault.rank("user-a") == 1 and vault.rank("admin") == 3
        v = IdentityVault.from_dict({"roles": {"auditor": 2, "user": 5},
                                     "identities": {"x": {"role": "auditor"},
                                                    "y": {"role": "user"}}})
        assert v.rank("x") == 2 and v.rank("y") == 5

    def test_unknown_role_is_normal_user(self):
        v = IdentityVault.from_dict({"identities": {"x": {"role": "wizard"}}})
        assert v.rank("x") == 1

    def test_identity_for_marker(self, vault):
        assert vault.identity_for_marker("hunter-b@example.com") == "user-b"


class TestInventory:
    def test_privilege_detection(self, vault):
        inv = {(f.method, f.template): f for f in
               BflaTester(_corpus(vault), vault, lambda c, e: (0, "")).inventory()}
        assert inv[("GET", "/v1/admin/users")].privileged
        assert inv[("GET", "/v1/reports/{int}")].privileged  # only admin succeeded
        assert "only seen succeeding" in inv[("GET", "/v1/reports/{int}")].reason
        assert not inv[("GET", "/v1/me")].privileged  # user-a succeeded too
        assert inv[("GET", "/v1/settings")].privileged  # user-a got 403
        assert set(inv[("GET", "/v1/settings")].roles_ok) == {"admin"}

    def test_openapi_admin_path_is_privileged_by_name(self, vault, tmp_path):
        spec = tmp_path / "api.yaml"
        spec.write_text("openapi: 3.0.0\nservers: [{url: 'https://api.example.com'}]\n"
                        "paths:\n  /internal/flags: {get: {}}\n  /public/news: {get: {}}\n")
        c = Corpus(scope_policy=ScopePolicy(in_scope=["api.example.com"]), identity_vault=vault)
        c.import_openapi(str(spec))
        inv = {f.template: f for f in BflaTester(c, vault, lambda a, b: (0, "")).inventory()}
        flags = inv["/internal/flags"]
        assert flags.privileged and "administrative" in flags.reason
        assert not inv["/public/news"].privileged


# ── agent / end to end ───────────────────────────────────────────────────────


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
    a.corpus = _corpus(vault)
    return a


def _serve(monkeypatch, fn):
    calls = []

    def popen(argv, **kw):
        text = " ".join(argv)
        calls.append(text)

        class P:
            returncode = 0
            stdout = None

            def communicate(self, input=None, timeout=None):
                return fn(text), ""
        return P()
    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", popen)
    return calls


def vulnerable(argv):
    """Admin user list checks only that *someone* is logged in."""
    if "-X OPTIONS" in argv:
        return http(204, headers="Allow: GET, PUT, DELETE, OPTIONS\r\n")
    authed = A_SESSION in argv or B_SESSION in argv or ADMIN_TOKEN in argv
    if "/admin/users" in argv:
        return http(200, USERS) if authed else http(401, '{"error": "unauthorized"}')
    if ADMIN_TOKEN in argv:
        return http(200, "{}")
    return http(403, '{"error": "forbidden"}')


def secure(argv):
    if "-X OPTIONS" in argv:
        return http(204, headers="Allow: GET\r\n")
    if ADMIN_TOKEN in argv:
        return http(200, USERS if "/admin/users" in argv else "{}")
    return http(403, '{"error": "forbidden"}')


class TestMatrix:
    def test_bfla_found_and_confirmed(self, agent, monkeypatch):
        calls = _serve(monkeypatch, vulnerable)
        out = agent.bfla_scan()
        row = next(r for r in out["matrix"]
                   if r["function"]["template"] == "/v1/admin/users")
        assert row["baseline"]["identity"] == "admin"
        assert set(row["markers"]) == {"hunter-a@example.com", "hunter-b@example.com"}
        assert row["cells"]["user-a"]["verdict"] == "exposed"
        assert row["cells"]["user-a"]["owner_marker"] == "hunter-b@example.com"  # not its own
        assert row["cells"]["anonymous"]["verdict"] == "denied"
        bfla = [f for f in agent.findings if f.vuln_class == "bfla"]
        assert bfla and all(f.confirmed for f in bfla), [f.proof for f in bfla]
        f = next(f for f in bfla if f.attacker_identity == "user-a")
        assert f.victim_identity == "user-b"
        assert f.validation["verdict"] == "ready_for_validator", f.validation
        assert "PUT" in f.description and "DELETE" in f.description  # siblings, untested
        assert not any("-X PUT" in c or "-X DELETE" in c for c in calls)

    def test_secure_no_findings(self, agent, monkeypatch):
        _serve(monkeypatch, secure)
        out = agent.bfla_scan()
        cells = [c["verdict"] for r in out["matrix"] for c in r["cells"].values()]
        assert cells and set(cells) == {"denied"}
        assert agent.findings == []

    def test_anonymous_access_is_auth_bypass(self, agent, monkeypatch):
        _serve(monkeypatch, lambda argv: http(204, headers="Allow: GET\r\n")
               if "-X OPTIONS" in argv else http(200, USERS))
        agent.bfla_scan(discover_siblings=False)
        anon = [f for f in agent.findings if f.attacker_identity == "anonymous"]
        assert anon and anon[0].vuln_class == "auth bypass"

    def test_baseline_without_markers_proves_nothing(self, agent, monkeypatch):
        _serve(monkeypatch, lambda argv: http(200, '{"ok": true}'))
        out = agent.bfla_scan(discover_siblings=False)
        assert all("no other identity's markers" in (r["baseline"] or {}).get("detail", "")
                   for r in out["matrix"] if r["baseline"])
        assert agent.findings == []

    def test_state_changing_function_not_run(self, agent, monkeypatch):
        calls = _serve(monkeypatch, vulnerable)
        agent.corpus.add("har", "DELETE", "https://api.example.com/v1/admin/users/9",
                         {"Authorization": f"Bearer {ADMIN_TOKEN}"}, "", 204)
        out = agent.bfla_scan(discover_siblings=False)
        row = next(r for r in out["matrix"] if r["function"]["method"] == "DELETE")
        assert row["note"].startswith("not_run") and row["baseline"] is None
        assert not any("-X DELETE" in c for c in calls)

    def test_inventory_only_sends_nothing(self, agent, monkeypatch):
        calls = _serve(monkeypatch, vulnerable)
        out = agent.bfla_scan(inventory_only=True)
        assert out["inventory"] and out["matrix"] == [] and calls == []

    def test_action_summary_has_matrix(self, agent, monkeypatch):
        _serve(monkeypatch, vulnerable)
        text = agent._process_bfla_action({})
        assert "| function | user-a | user-b | admin | anonymous |" in text
        assert "siblings via OPTIONS: DELETE, PUT" in text


def test_render_matrix_empty():
    assert "No privileged functions" in render_matrix([], ["a"])


def test_requires_identities():
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    assert "identities" in a.bfla_scan()["refused"]
