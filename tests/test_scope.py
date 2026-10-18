"""Tests for scope enforcement (hackbot.core.scope) and its integration."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.engine import AIEngine
from hackbot.core.runner import ToolRunner
from hackbot.core.scope import (
    ScopeAuditLog,
    ScopePolicy,
    ScopeRule,
    ScopeVerdict,
    extract_targets,
)


@pytest.fixture
def policy():
    return ScopePolicy(
        in_scope=[
            "*.example.com",
            "example.com",
            "10.0.0.0/24",
            "https://shop.test.com/api",
        ],
        out_of_scope=["admin.example.com", "10.0.0.13"],
    )


# ── Rules ────────────────────────────────────────────────────────────────────


class TestRules:
    def test_exact_host(self):
        rule = ScopeRule.parse("example.com")
        assert rule.matches("example.com")
        assert not rule.matches("api.example.com")

    def test_wildcard_excludes_apex(self):
        rule = ScopeRule.parse("*.example.com")
        assert rule.matches("api.example.com")
        assert rule.matches("a.b.example.com")
        assert not rule.matches("example.com")

    def test_lookalike_domains_never_match(self):
        rule = ScopeRule.parse("*.example.com")
        assert not rule.matches("evilexample.com")
        assert not rule.matches("example.com.evil.net")

    def test_cidr(self):
        rule = ScopeRule.parse("10.0.0.0/24")
        assert rule.matches("10.0.0.7")
        assert not rule.matches("10.0.1.7")
        assert not rule.matches("example.com")

    def test_url_path_prefix(self):
        rule = ScopeRule.parse("https://shop.test.com/api")
        assert rule.matches("shop.test.com", "/api")
        assert rule.matches("shop.test.com", "/api/v1/users?id=1")
        assert not rule.matches("shop.test.com", "/apiv2")
        assert not rule.matches("shop.test.com", "/admin")

    @pytest.mark.parametrize("bad", ["", "not a host", "*.", "10.0.0.0/99"])
    def test_invalid_rules_raise(self, bad):
        with pytest.raises(ValueError):
            ScopeRule.parse(bad)


# ── Target extraction ────────────────────────────────────────────────────────


class TestExtraction:
    def test_url_and_host(self):
        ext = extract_targets("nuclei -u https://a.example.com/x -o out.txt")
        assert [t.host for t in ext.targets] == ["a.example.com"]
        assert ext.uses_network

    def test_output_and_wordlist_files_are_not_targets(self):
        ext = extract_targets("ffuf -u https://www.example.com/FUZZ -w words.txt -o res.json")
        assert [t.host for t in ext.targets] == ["www.example.com"]

    def test_host_port(self):
        ext = extract_targets("nc -zv example.com:443")
        assert ext.targets[0].host == "example.com"

    def test_cidr_target(self):
        ext = extract_targets("nmap -sn 10.0.0.0/25")
        assert ext.targets[0].is_cidr

    def test_payload_urls_are_not_targets(self):
        ext = extract_targets(
            "curl -d 'url=http://169.254.169.254/latest/' https://api.example.com/fetch"
        )
        assert [t.host for t in ext.targets] == ["api.example.com"]
        assert ext.payload_urls == ["http://169.254.169.254/latest/"]

    def test_python_inline_code_urls_are_targets(self):
        ext = extract_targets("python3 -c \"import requests; requests.get('https://evil.org/x')\"")
        assert [t.host for t in ext.targets] == ["evil.org"]

    def test_script_file_urls_are_targets(self, tmp_path):
        script = tmp_path / "poc.py"
        script.write_text("import requests\nrequests.get('https://evil.org/steal')\n")
        ext = extract_targets(f"python3 {script}")
        assert [t.host for t in ext.targets] == ["evil.org"]

    def test_list_file_contents_are_checked(self, tmp_path):
        hosts = tmp_path / "hosts.txt"
        hosts.write_text("api.example.com\n# comment\nevil.org\n")
        ext = extract_targets(f"httpx -l {hosts}")
        assert sorted(t.host for t in ext.targets) == ["api.example.com", "evil.org"]

    def test_missing_list_file_is_an_error(self):
        ext = extract_targets("nmap -iL /nonexistent/hosts.txt")
        assert ext.errors

    def test_pipeline_stages(self):
        ext = extract_targets("nmap -p 80 example.com | grep open")
        assert [t.host for t in ext.targets] == ["example.com"]


# ── Decisions ────────────────────────────────────────────────────────────────


class TestDecisions:
    @pytest.mark.parametrize("cmd", [
        "nmap -sV example.com",
        "curl -s https://api.example.com/x",
        "nmap 10.0.0.128/25",                        # avoids excluded 10.0.0.13
        "curl https://shop.test.com/api/v1",
        "nmap -p 80 example.com | grep open",
    ])
    def test_allowed(self, policy, cmd):
        assert policy.check_command(cmd).verdict == ScopeVerdict.ALLOW

    @pytest.mark.parametrize("cmd", [
        "nmap -sV evil.com",
        "curl https://evilexample.com",
        "curl https://admin.example.com/",          # explicitly excluded
        "nmap 10.0.0.13",                            # excluded IP inside in-scope CIDR
        "nmap 10.0.0.0/16",                          # wider than in-scope network
        "curl https://shop.test.com/admin",          # outside path prefix
        "nuclei -u https://a.example.com -u https://evil.org",  # one bad target
    ])
    def test_denied(self, policy, cmd):
        d = policy.check_command(cmd)
        assert d.verdict == ScopeVerdict.DENY
        assert d.out_of_scope

    def test_cidr_overlapping_exclusion_denied(self, policy):
        assert policy.check_command("nmap 10.0.0.0/28").verdict == ScopeVerdict.DENY

    def test_network_tool_without_target_is_unknown(self, policy):
        assert policy.check_command("httpx -silent").verdict == ScopeVerdict.UNKNOWN

    def test_local_tool_is_allowed(self, policy):
        assert policy.check_command("grep -i password notes.txt").verdict == ScopeVerdict.ALLOW

    def test_missing_list_file_denied(self, policy):
        assert policy.check_command("nmap -iL /nonexistent").verdict == ScopeVerdict.DENY


# ── Parsing scope definitions ────────────────────────────────────────────────


class TestPolicyParsing:
    def test_plain_text(self):
        p = ScopePolicy.from_text("""
            # program scope
            *.example.com
            !admin.example.com
            [out]
            legacy.example.com
        """)
        assert [r.raw for r in p.in_scope] == ["*.example.com"]
        assert [r.raw for r in p.out_of_scope] == ["admin.example.com", "legacy.example.com"]

    def test_yaml(self, tmp_path):
        f = tmp_path / "scope.yaml"
        f.write_text("name: acme\nin_scope:\n  - '*.acme.com'\nout_of_scope:\n  - pay.acme.com\n")
        p = ScopePolicy.from_file(str(f))
        assert p.name == "acme"
        assert not p.check_raw_target("https://pay.acme.com/")[0]
        assert p.check_raw_target("https://www.acme.com/")[0]

    def test_rules_string(self):
        p = ScopePolicy.from_rules_string("*.example.com, !admin.example.com")
        assert p is not None
        assert not p.check_raw_target("admin.example.com")[0]

    def test_free_text_scope_is_not_rules(self):
        assert ScopePolicy.from_rules_string("web app only, no DoS") is None

    def test_from_target_is_exact_host(self):
        p = ScopePolicy.from_target("https://app.example.com/login")
        assert p.check_raw_target("app.example.com")[0]
        assert not p.check_raw_target("api.example.com")[0]


# ── ToolRunner integration ───────────────────────────────────────────────────


class _FakePopen:
    calls = []

    def __init__(self, argv, **kwargs):
        _FakePopen.calls.append(argv)
        self.returncode = 0

    def communicate(self, input=None, timeout=None):
        return ("ok", "")


@pytest.fixture
def fake_popen(monkeypatch):
    _FakePopen.calls = []
    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", _FakePopen)
    return _FakePopen


def _runner(policy, tmp_path, approve=None, auto_confirm=False):
    return ToolRunner(
        allowed_tools=["nmap", "curl", "httpx", "grep"],
        safe_mode=True,
        auto_confirm=auto_confirm,
        scope_policy=policy,
        scope_audit=ScopeAuditLog(tmp_path / "audit.jsonl"),
        on_approve=approve,
    )


class TestRunnerIntegration:
    def test_out_of_scope_never_executes(self, policy, tmp_path, fake_popen):
        r = _runner(policy, tmp_path, approve=lambda c, why: True, auto_confirm=True)
        res = r.execute("nmap -sV evil.com")
        assert not res.success
        assert "OUT OF SCOPE" in res.stderr
        assert fake_popen.calls == []

    def test_in_scope_executes(self, policy, tmp_path, fake_popen):
        r = _runner(policy, tmp_path)
        res = r.execute("nmap -sV example.com")
        assert res.success
        assert fake_popen.calls

    def test_unknown_without_approver_is_refused(self, policy, tmp_path, fake_popen):
        r = _runner(policy, tmp_path, auto_confirm=True)
        res = r.execute("httpx -silent")
        assert "SCOPE UNVERIFIED" in res.stderr
        assert fake_popen.calls == []

    def test_unknown_with_human_approval_runs(self, policy, tmp_path, fake_popen):
        r = _runner(policy, tmp_path, approve=lambda c, why: True)
        assert r.execute("httpx -silent").success

    def test_auto_confirm_style_on_confirm_does_not_bypass(self, policy, tmp_path, fake_popen):
        """The GUI wires on_confirm to auto_confirm; that must not satisfy scope."""
        r = _runner(policy, tmp_path, auto_confirm=True)
        r.on_confirm = lambda c, why: True
        assert "SCOPE UNVERIFIED" in r.execute("httpx -silent").stderr
        assert fake_popen.calls == []

    def test_audit_log_records_decisions(self, policy, tmp_path, fake_popen):
        r = _runner(policy, tmp_path)
        r.execute("nmap example.com")
        r.execute("nmap evil.com")
        lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert [x["action"] for x in lines] == ["allowed", "blocked"]
        assert lines[1]["out_of_scope"] == ["evil.com"]

    def test_no_policy_keeps_legacy_behaviour(self, tmp_path, fake_popen):
        r = _runner(None, tmp_path)
        assert r.execute("nmap evil.com").success


# ── AgentMode integration ────────────────────────────────────────────────────


def _agent(scope_cfg=None):
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["nmap"], safe_mode=True)
    config.scope = scope_cfg or ScopeConfig(audit_log=False)
    engine = MagicMock(spec=AIEngine)
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        return AgentMode(engine=engine, config=config)


class TestAgentIntegration:
    def test_auto_policy_from_target(self):
        agent = _agent()
        p = agent.build_scope_policy("app.example.com")
        assert p.check_raw_target("app.example.com")[0]
        assert not p.check_raw_target("other.example.com")[0]

    def test_scope_file_takes_precedence(self, tmp_path):
        f = tmp_path / "scope.txt"
        f.write_text("*.example.com\n")
        agent = _agent()
        p = agent.build_scope_policy("app.example.com", scope="evil.org", scope_file=str(f))
        assert p.check_raw_target("x.example.com")[0]
        assert not p.check_raw_target("evil.org")[0]

    def test_rule_string_scope(self):
        agent = _agent()
        p = agent.build_scope_policy("www.example.com", scope="*.example.com,!admin.example.com")
        assert not p.check_raw_target("admin.example.com")[0]

    def test_enforcement_can_be_disabled(self):
        agent = _agent(ScopeConfig(enforce=False, audit_log=False))
        assert agent.build_scope_policy("example.com") is None

    def test_start_refuses_out_of_scope_target(self, tmp_path):
        f = tmp_path / "scope.txt"
        f.write_text("*.example.com\n")
        agent = _agent()
        msg = agent.start("evil.org", scope_file=str(f))
        assert msg.startswith("⛔")
        assert not agent.is_running
        agent.engine.chat.assert_not_called()

    def test_start_refuses_invalid_scope_file(self, tmp_path):
        f = tmp_path / "scope.txt"
        f.write_text("not a valid host rule\n")
        agent = _agent()
        assert agent.start("example.com", scope_file=str(f)).startswith("⛔")

    def test_fuzz_refused_out_of_scope(self, tmp_path, fake_popen):
        agent = _agent()
        agent.runner.scope_policy = ScopePolicy(in_scope=["example.com"])
        out = agent._process_fuzz_action({"target_url": "https://evil.org/x", "parameter": "q"})
        assert "BLOCKED" in out
        assert fake_popen.calls == []

    def test_fuzz_needs_one_human_approval(self, fake_popen):
        agent = _agent()
        agent.runner.scope_policy = ScopePolicy(in_scope=["example.com"])
        approvals = []
        agent.runner.on_approve = lambda c, why: approvals.append(c) or True
        agent.runner.allowed_tools = ["curl"]
        agent._process_fuzz_action({"target_url": "https://example.com/s", "parameter": "q"})
        assert len(approvals) == 1
        assert fake_popen.calls  # payloads were sent after the single approval


# ── Other network paths ──────────────────────────────────────────────────────


def test_proxy_scope_is_label_aware():
    from hackbot.core.proxy import ProxyEngine

    engine = ProxyEngine()
    engine.set_scope(["example.com"])
    assert engine.in_scope("example.com")
    assert engine.in_scope("api.example.com:443")
    assert not engine.in_scope("evilexample.com")
    engine.clear_scope()
    assert engine.in_scope("anything.org")


def test_http_client_refuses_out_of_scope():
    from hackbot.core.zeroday_active import HttpClient, ScanConfig

    client = HttpClient(ScanConfig(scope_policy=ScopePolicy(in_scope=["example.com"])))
    client.session.request = MagicMock()
    assert client.get("https://evil.org/") is None
    client.session.request.assert_not_called()


def test_http_client_stops_at_out_of_scope_redirect():
    from hackbot.core.zeroday_active import HttpClient, ScanConfig

    client = HttpClient(ScanConfig(scope_policy=ScopePolicy(in_scope=["example.com"])))
    redirect = MagicMock(is_redirect=True, status_code=302, url="https://example.com/a",
                         headers={"Location": "https://evil.org/b"}, content=b"")
    client.session.request = MagicMock(return_value=redirect)
    resp = client.get("https://example.com/a")
    assert resp is redirect
    assert client.session.request.call_count == 1
    assert client.session.request.call_args.kwargs["url"] == "https://example.com/a"


def test_scope_config_round_trip(tmp_path, monkeypatch):
    from hackbot import config as cfgmod

    monkeypatch.setattr(cfgmod, "CONFIG_FILE", tmp_path / "config.yaml")
    monkeypatch.setattr(cfgmod, "ensure_dirs", lambda: None)
    cfg = HackBotConfig()
    cfg.scope = ScopeConfig(file="/tmp/scope.yaml", sample_limit=3)
    cfgmod.save_config(cfg)
    loaded = cfgmod.load_config()
    assert loaded.scope.file == "/tmp/scope.yaml"
    assert loaded.scope.sample_limit == 3
    assert loaded.scope.enforce is True
