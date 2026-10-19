"""Tests for the identity vault (multi-account credentials, placeholders, redaction)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityError, IdentityVault
from hackbot.core.runner import ToolRunner
from hackbot.core.scope import ScopePolicy

# Fake test credentials, built at runtime so secret scanners stay quiet.
A_SESSION = "sess-" + "a" * 24
B_TOKEN = "tok-" + "b" * 30
ADMIN_KEY = "key-" + "c" * 20

VAULT_YAML = f"""
max_identities: 3
identities:
  user-a:
    role: user
    tenant: t1
    cookies: {{session: "{A_SESSION}", theme: dark}}
    markers: ["hunter-a@example.com", "1001"]
    owned: {{order: ["5001"]}}
  user-b:
    role: user
    tenant: t1
    bearer: "{B_TOKEN}"
    markers: ["hunter-b@example.com", "1002"]
    owned: {{order: ["5002"]}}
  admin:
    role: admin
    headers: {{X-Api-Key: "{ADMIN_KEY}"}}
"""


@pytest.fixture
def vault_file(tmp_path):
    f = tmp_path / "identities.yaml"
    f.write_text(VAULT_YAML)
    return f


@pytest.fixture
def vault(vault_file):
    return IdentityVault.from_file(str(vault_file))


SECRETS = (A_SESSION, B_TOKEN, ADMIN_KEY)


class TestVault:
    def test_loads_with_builtin_anonymous(self, vault):
        assert set(vault.names()) == {"user-a", "user-b", "admin", "anonymous"}
        assert vault.get("anonymous").auth_headers() == {}

    def test_account_limit_enforced(self, tmp_path):
        f = tmp_path / "i.yaml"
        f.write_text("max_identities: 1\nidentities:\n  a: {role: user}\n  b: {role: user}\n")
        with pytest.raises(IdentityError, match="max_identities"):
            IdentityVault.from_file(str(f))

    @pytest.mark.parametrize("bad", ["anonymous", "has space", "x" * 50])
    def test_invalid_names(self, bad):
        with pytest.raises(IdentityError):
            IdentityVault.from_dict({"identities": {bad: {}}})

    def test_public_view_never_contains_secrets(self, vault):
        dumped = json.dumps(vault.public_view()) + vault.summary()
        for secret in SECRETS:
            assert secret not in dumped
        assert "hunter-b@example.com" in dumped and "bearer" in dumped

    def test_auth_headers(self, vault):
        assert vault.get("user-a").auth_headers()["Cookie"] == f"session={A_SESSION}; theme=dark"
        assert vault.get("user-b").auth_headers()["Authorization"] == f"Bearer {B_TOKEN}"
        assert vault.get("admin").auth_headers()["X-Api-Key"] == ADMIN_KEY

    def test_ownership_ledger(self, vault):
        assert vault.owner_of("5002") == "user-b"
        assert vault.owner_of("5002", "invoice") is None
        vault.add_owned("user-a", "invoice", "inv-9")
        assert vault.owner_of("inv-9") == "user-a"


class TestPlaceholders:
    def test_expand(self, vault):
        out = vault.expand(
            '-H "Authorization: Bearer {{bearer:user-b}}" -H "Cookie: {{cookie:user-a}}"'
        )
        assert B_TOKEN in out and A_SESSION in out
        assert "{{" not in out

    @pytest.mark.parametrize("text,err", [
        ("{{cookie:ghost}}", "unknown identity"),
        ("{{bearer:user-a}}", "no bearer"),
        ("{{cookie:user-b}}", "no cookies"),
        ("{{header:admin:X-Other}}", "no header"),
    ])
    def test_check_errors(self, vault, text, err):
        assert err in vault.check_placeholders(text)

    def test_redaction_labels(self, vault):
        text = f"echo {B_TOKEN} and session={A_SESSION}; theme=dark and {ADMIN_KEY}"
        red = vault.redact(text)
        for secret in SECRETS:
            assert secret not in red
        assert "<redacted:user-b.bearer>" in red
        assert "<redacted:admin.header.X-Api-Key>" in red


# ── Runner ───────────────────────────────────────────────────────────────────


class _Popen:
    argv = []
    output = ""

    def __init__(self, argv, **kwargs):
        _Popen.argv.append(argv)
        self.returncode = 0
        self.stdout = None

    def communicate(self, input=None, timeout=None):
        return (_Popen.output, "")


@pytest.fixture
def popen(monkeypatch):
    _Popen.argv, _Popen.output = [], ""
    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", _Popen)
    return _Popen


def _runner(vault=None):
    return ToolRunner(allowed_tools=["curl", "grep"], safe_mode=True, identity_vault=vault,
                      scope_policy=ScopePolicy(in_scope=["api.example.com"]))


class TestRunner:
    CMD = 'curl -s -H "Authorization: Bearer {{bearer:user-b}}" https://api.example.com/v1/me'

    def test_expanded_only_in_argv(self, vault, popen):
        popen.output = '{"email": "hunter-b@example.com"}'
        res = _runner(vault).execute(self.CMD)
        assert f"Authorization: Bearer {B_TOKEN}" in popen.argv[0]
        assert "{{bearer:user-b}}" in res.command  # what the AI and logs see
        assert B_TOKEN not in res.command

    def test_echoed_secret_is_redacted_everywhere(self, vault, popen):
        popen.output = f"debug: auth={B_TOKEN}"
        r = _runner(vault)
        res = r.execute(self.CMD)
        assert B_TOKEN not in res.stdout and "<redacted:user-b.bearer>" in res.stdout
        assert B_TOKEN not in r.history[-1].stdout

    def test_placeholder_without_vault_blocked(self, popen):
        res = _runner(None).execute(self.CMD)
        assert "no identities file" in res.stderr and popen.argv == []

    def test_unknown_identity_blocked(self, vault, popen):
        res = _runner(vault).execute(self.CMD.replace("user-b", "ghost"))
        assert "unknown identity" in res.stderr and popen.argv == []

    def test_scope_still_enforced(self, vault, popen):
        res = _runner(vault).execute(self.CMD.replace("api.example.com", "evil.org"))
        assert "OUT OF SCOPE" in res.stderr and popen.argv == []

    def test_pipeline_expands_and_redacts(self, vault, popen, monkeypatch):
        popen.output = f"line {B_TOKEN}"
        res = _runner(vault).execute(self.CMD + " | grep line")
        assert any(f"Authorization: Bearer {B_TOKEN}" in a for argv in popen.argv for a in argv)
        assert B_TOKEN not in res.stdout


# ── Agent ────────────────────────────────────────────────────────────────────


def _agent():
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    engine = MagicMock(spec=AIEngine)
    engine.chat.return_value = "ok"
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        return AgentMode(engine=engine, config=config)


def test_agent_prompt_lists_identities_without_secrets(vault_file):
    agent = _agent()
    with patch.object(agent, "_process_actions_loop", return_value="ok"), \
            patch.object(agent, "_auto_save"):
        agent.start("api.example.com", identities_file=str(vault_file))
    assert agent.runner.identity_vault is agent.identity_vault
    context = " ".join(m.content for m in agent.conversation.messages)
    assert "user-b (role=user" in context and "{{cookie:user-b}}" in context
    for secret in SECRETS:
        assert secret not in context


def test_agent_rejects_bad_identities_file(tmp_path):
    f = tmp_path / "i.yaml"
    f.write_text("identities:\n  'bad name': {}\n")
    msg = _agent().start("api.example.com", identities_file=str(f))
    assert msg.startswith("⛔ Invalid identities file")


def test_victim_identifier_filled_from_markers(vault):
    from hackbot.core.runner import ToolResult
    from hackbot.modes.agent import AgentStep

    agent = _agent()
    agent._assessment_id = None
    agent._rag_enabled = False
    agent.identity_vault = vault
    agent.target = "api.example.com"
    out = '{"order": 5002, "email": "hunter-b@example.com"}'
    result = ToolResult(
        tool="curl", command="curl -s -H 'Cookie: {{cookie:user-a}}' https://api.example.com/o/5002",
        stdout=out, stderr="", return_code=0, duration=0.1, success=True)
    agent.steps.append(AgentStep(step_num=1, action="execute", description="", tool_result=result))
    agent._record_finding({
        "title": "IDOR on /o/{id}", "severity": "High", "vuln_class": "idor",
        "behavior": "user-a's session reads order 5002 owned by user-b",
        "boundary": "object-level authorization between customer accounts",
        "impact": "user-a read user-b's order including user-b's email",
        "evidence_refs": [{"step": 1, "excerpt": '"email": "hunter-b@example.com"'}],
        "attacker_identity": "user-a", "victim_identity": "user-b",
        "privileges_required": "user",
    })
    f = agent.findings[0]
    assert f.confirmed
    assert f.victim_identifier == "hunter-b@example.com"
    assert next(q for q in f.validation["questions"] if q["q"] == "Q6")["status"] == "pass"
