"""Tests for Phase 1.3: boundary types, tenant isolation, session-lifecycle checks."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.boundaries import annotate_boundary
from hackbot.core.corpus import Corpus
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityVault
from hackbot.core.scope import ScopePolicy
from hackbot.core.validation import FindingValidator, RuleSet

A_TOKEN = "tok-" + "a" * 30
B_TOKEN = "tok-" + "b" * 30
C_TOKEN = "tok-" + "c" * 30

VALIDATOR_MD = """## Never-Submit List

```
Session not invalidated on logout
Self-XSS
```
"""


def http(status, body=""):
    return f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\r\n{body}"


@pytest.fixture
def vault():
    return IdentityVault.from_dict({"identities": {
        "user-a": {"role": "user", "tenant": "acme", "bearer": A_TOKEN,
                   "markers": ["a@acme.test"]},
        "user-b": {"role": "user", "tenant": "acme", "bearer": B_TOKEN,
                   "markers": ["b@acme.test"]},
        "user-c": {"role": "user", "tenant": "globex", "bearer": C_TOKEN,
                   "markers": ["c@globex.test"]},
    }, "max_identities": 3})


# ── boundary annotation ──────────────────────────────────────────────────────


class TestBoundary:
    def test_types(self, vault):
        assert annotate_boundary({"attacker_identity": "anonymous", "victim_identity": "user-a",
                                  "vuln_class": "auth bypass"}, vault)["boundary_type"] == \
            "authentication"
        same = annotate_boundary({"attacker_identity": "user-a", "victim_identity": "user-b",
                                  "vuln_class": "idor", "title": "IDOR"}, vault)
        assert same["boundary_type"] == "object_level"
        assert annotate_boundary({"attacker_identity": "user-a", "victim_identity": "user-b",
                                  "vuln_class": "bfla"}, vault)["boundary_type"] == "function_level"

    def test_cross_tenant(self, vault):
        act = annotate_boundary({"attacker_identity": "user-a", "victim_identity": "user-c",
                                 "vuln_class": "idor", "title": "IDOR: GET /x"}, vault)
        assert act["boundary_type"] == "tenant_isolation"
        assert act["title"] == "Cross-tenant IDOR: GET /x"
        assert (act["attacker_tenant"], act["victim_tenant"]) == ("acme", "globex")
        assert "tenant isolation" in act["boundary"]

    def test_session_type_kept(self, vault):
        act = annotate_boundary({"boundary_type": "session_lifecycle",
                                 "attacker_identity": "user-a"}, vault)
        assert act["boundary_type"] == "session_lifecycle"


# ── validator rules ──────────────────────────────────────────────────────────


@pytest.fixture
def validator(tmp_path):
    v = tmp_path / "validator.md"
    v.write_text(VALIDATOR_MD)
    return FindingValidator(RuleSet.load(v, tmp_path / "none"))


def _confirmed(**over):
    f = {"raw_title": "x", "severity": "Medium", "verification": "confirmed",
         "privileges_required": "user", "proof": {
             "checks": [{"name": "impact", "passed": True},
                        {"name": "impact_evidence", "passed": True}],
             "verified_refs": [{"excerpt": "c@globex.test", "source": "observed",
                                "supports": "both", "step": 1, "command": ""}]}}
    f.update(over)
    return f


def test_tenant_claim_needs_two_tenants(validator):
    f = _confirmed(boundary_type="tenant_isolation", attacker_tenant="acme",
                   victim_tenant="acme", raw_title="Cross-tenant listing")
    assert validator.validate(f).label == "KILL Q6"


@pytest.mark.parametrize("title,killed", [
    ("Session not invalidated after logout: old token accepted", True),
    ("Session not invalidated after password change: old token accepted", False),
    ("Privileges not revoked after role downgrade", False),
])
def test_logout_rule_only_hits_logout(validator, title, killed):
    res = validator.validate(_confirmed(raw_title=title, vuln_class="session management"))
    q7 = next(q for q in res.questions if q.q == "Q7")
    assert (q7.status == "fail") is killed


# ── vault retired snapshots ──────────────────────────────────────────────────


def test_retired_snapshot(vault):
    import copy

    old = copy.deepcopy(vault.get("user-a"))
    old.name, old.bearer = "user-a.before", "old-" + "z" * 30
    vault.add_retired(old)
    assert "user-a.before" not in vault.names()
    assert vault.get("user-a.before").bearer == old.bearer
    assert old.bearer in vault.expand("{{bearer:user-a.before}}")
    assert vault.check_placeholders("{{bearer:user-a.before}}") is None
    assert old.bearer not in vault.redact(f"x {old.bearer}")


# ── agent end to end ─────────────────────────────────────────────────────────


@pytest.fixture
def agent(vault):
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a._assessment_id, a._rag_enabled, a.target = None, False, "api.example.com"
    a.scope_policy = a.runner.scope_policy = ScopePolicy(in_scope=["api.example.com"])
    a.identity_vault = a.runner.identity_vault = vault
    a.corpus = Corpus(scope_policy=a.scope_policy, identity_vault=vault)
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


LEAKY = json.dumps({"members": [{"email": "a@acme.test"}, {"email": "c@globex.test"}]})


class TestTenantScan:
    def test_cross_tenant_leak_confirmed(self, agent, monkeypatch):
        agent.corpus.add("har", "GET", "https://api.example.com/v1/team/members",
                         {"Authorization": f"Bearer {A_TOKEN}"}, "", 200, {}, LEAKY)
        _serve(monkeypatch, lambda argv: http(200, LEAKY))
        out = agent.tenant_scan()
        assert [lead["status"] for lead in out["leads"]] == ["confirmed"]
        f = agent.findings[0]
        assert f.confirmed, f.proof
        assert f.title.startswith("Cross-tenant")
        assert f.boundary_type == "tenant_isolation"
        assert (f.attacker_tenant, f.victim_tenant) == ("acme", "globex")
        assert f.validation["verdict"] == "ready_for_validator", f.validation

    def test_same_tenant_data_is_not_a_leak(self, agent, monkeypatch):
        body = json.dumps({"members": [{"email": "a@acme.test"}, {"email": "b@acme.test"}]})
        agent.corpus.add("har", "GET", "https://api.example.com/v1/team/members",
                         {"Authorization": f"Bearer {A_TOKEN}"}, "", 200, {}, body)
        calls = _serve(monkeypatch, lambda argv: http(200, body))
        assert agent.tenant_scan()["leads"] == [] and calls == []

    def test_not_reproduced_is_no_finding(self, agent, monkeypatch):
        agent.corpus.add("har", "GET", "https://api.example.com/v1/team/members",
                         {"Authorization": f"Bearer {A_TOKEN}"}, "", 200, {}, LEAKY)
        _serve(monkeypatch, lambda argv: http(200, '{"members": []}'))
        out = agent.tenant_scan()
        assert out["leads"][0]["status"] == "not_reproduced"
        assert agent.findings == []

    def test_identities_without_tenant_ignored(self, agent, monkeypatch):
        for n in ("user-a", "user-b", "user-c"):
            agent.identity_vault.get(n).tenant = ""
        agent.corpus.add("har", "GET", "https://api.example.com/v1/team/members",
                         {"Authorization": f"Bearer {A_TOKEN}"}, "", 200, {}, LEAKY)
        assert agent.tenant_scan(confirm=False)["leads"] == []


class FakeSessions:
    """A server whose behaviour for the OLD token depends on the event."""

    def __init__(self, revokes_on_event: bool):
        self.revokes = revokes_on_event
        self.event_happened = False

    def __call__(self, argv):
        if A_TOKEN in argv:
            if self.event_happened and self.revokes:
                return http(401, '{"error": "token revoked"}')
            return http(200, json.dumps({"email": "a@acme.test", "plan": "pro"}))
        return http(401, "{}")


def _profile(agent):
    return agent.corpus.add("har", "GET", "https://api.example.com/v1/me",
                            {"Authorization": f"Bearer {A_TOKEN}"}, "", 200, {},
                            '{"email": "a@acme.test"}')


class TestSessionLifecycle:
    def test_password_change_old_token_still_valid(self, agent, monkeypatch, tmp_path):
        server = FakeSessions(revokes_on_event=False)
        calls = _serve(monkeypatch, server)
        _profile(agent)
        begin = agent.session_begin("user-a")
        assert begin["verdict"] == "begun" and begin["marker"] == "a@acme.test"
        server.event_happened = True  # the hunter changes the password in the app
        # the hunter reloads fresh credentials: a NEW vault object
        fresh = IdentityVault.from_dict({"identities": {
            "user-a": {"role": "user", "tenant": "acme", "bearer": "new-" + "n" * 30,
                       "markers": ["a@acme.test"]}}})
        agent.session_event("user-a", "password_change", "changed in /settings")
        agent.identity_vault = agent.runner.identity_vault = fresh
        out = agent.session_verify("user-a")
        assert out["verdict"] == "still_valid"
        assert any(A_TOKEN in c for c in calls[-1:])  # the OLD token was used
        f = agent.findings[0]
        assert f.boundary_type == "session_lifecycle"
        assert not f.confirmed  # the event itself is not recorded yet
        assert any("lifecycle event itself" in m for m in f.proof["missing"])
        rec = tmp_path / "password-change.png"
        rec.write_bytes(b"\x89PNG fake screenshot")
        f = agent.attest_evidence(0, str(rec), "settings page: password updated")
        assert f.confirmed, f.proof
        assert f.validation["verdict"] == "ready_for_validator", f.validation
        dump = json.dumps(f.to_dict()) + json.dumps([s.tool_result.to_dict() for s in agent.steps
                                                     if s.tool_result])
        assert A_TOKEN not in dump

    def test_secure_server_invalidates(self, agent, monkeypatch):
        server = FakeSessions(revokes_on_event=True)
        _serve(monkeypatch, server)
        _profile(agent)
        agent.session_begin("user-a")
        server.event_happened = True
        agent.session_event("user-a", "password_change")
        assert agent.session_verify("user-a")["verdict"] == "invalidated"
        assert agent.findings == []

    def test_logout_finding_is_killed_by_never_submit(self, agent, monkeypatch, tmp_path):
        v = tmp_path / "validator.md"
        v.write_text(VALIDATOR_MD)
        agent.config.validation.validator_path = str(v)
        agent.config.validation.gotchas_path = str(tmp_path / "none")
        server = FakeSessions(revokes_on_event=False)
        _serve(monkeypatch, server)
        _profile(agent)
        agent.session_begin("user-a")
        server.event_happened = True
        agent.session_event("user-a", "logout")
        agent.session_verify("user-a")
        rec = tmp_path / "logout.png"
        rec.write_bytes(b"\x89PNG")
        f = agent.attest_evidence(0, str(rec))
        assert f.confirmed
        assert f.validation["label"] == "KILL Q7"

    def test_probe_must_prove_the_session(self, agent, monkeypatch):
        _serve(monkeypatch, lambda argv: http(200, '{"ok": true}'))
        _profile(agent)
        assert agent.session_begin("user-a")["verdict"] == "inconclusive"
        with pytest.raises(ValueError, match="did not prove"):
            agent.session_event("user-a", "password_change")

    def test_guards(self, agent, monkeypatch):
        _serve(monkeypatch, FakeSessions(False))
        with pytest.raises(ValueError, match="no GET in the corpus"):
            agent.session_begin("user-a")
        with pytest.raises(ValueError, match="begin for"):
            agent.session_event("user-b", "logout")
        _profile(agent)
        agent.session_begin("user-a")
        with pytest.raises(ValueError, match="event must be one of"):
            agent.session_event("user-a", "reboot")
        with pytest.raises(ValueError, match="record the lifecycle event"):
            agent.session_verify("user-a")
        with pytest.raises(Exception):
            agent.session_begin("anonymous")

    def test_non_get_probe_refused(self, agent, monkeypatch):
        _serve(monkeypatch, FakeSessions(False))
        ex = agent.corpus.add("har", "POST", "https://api.example.com/v1/me",
                              {"Authorization": f"Bearer {A_TOKEN}"}, "{}", 200, {},
                              '{"email": "a@acme.test"}')
        with pytest.raises(ValueError, match="GET/HEAD"):
            agent.session_begin("user-a", ex.id)
