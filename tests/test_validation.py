"""Tests for offline pre-validation (validator.md + ywh gotchas) and the handoff packet."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig, ValidationConfig
from hackbot.core.engine import AIEngine
from hackbot.core.runner import ToolResult
from hackbot.core.scope import ScopePolicy
from hackbot.core.validation import (
    VALIDATOR_PATH,
    FindingValidator,
    ProgramRules,
    RuleSet,
    Verdict,
    _find_gotchas,
)

VALIDATOR_MD = """---
name: validator
---
## Never-Submit List (instant kill if no chain)

```
Missing headers (CSP/HSTS/X-Frame-Options)
GraphQL introspection alone
Clickjacking without sensitive action PoC
CORS wildcard without credentialed exfil PoC
Self-XSS
Open redirect alone
SSRF DNS-only
Rate limit on non-critical forms
```

## Conditionally Valid (chain required)

```
Open redirect → + OAuth code theft → CHAIN REQUIRED
SSRF DNS-only → + internal data → CHAIN REQUIRED
```
"""

GOTCHAS_MD = """---
name: gotchas
---
## IDOR / BOLA

**Minimum proof**
- Two hunter-controlled accounts, A and B.
- Response containing B's data shown, with B's identifier visible.

**Common N/A**
- Sequential IDs without showing actual access.

## SQLi

**Minimum proof** (one of)
- Data extraction: sentinel value, table name, DB version returned.
"""


@pytest.fixture
def rules(tmp_path):
    v = tmp_path / "validator.md"
    v.write_text(VALIDATOR_MD)
    g = tmp_path / "gotchas.md"
    g.write_text(GOTCHAS_MD)
    return RuleSet.load(v, g)


@pytest.fixture
def validator(rules):
    return FindingValidator(rules)


@pytest.fixture
def scope():
    return ScopePolicy(in_scope=["*.example.com"])


def _finding(**over):
    f = {
        "raw_title": "IDOR on /v1/orders/{id}", "vuln_class": "idor", "severity": "High",
        "verification": "confirmed", "asset": "https://api.example.com/v1/orders/1002",
        "privileges_required": "user", "attacker_identity": "user-a",
        "victim_identity": "user-b", "victim_identifier": "victim@example.com",
        "description": "",
        "proof": {
            "checks": [{"name": "impact", "passed": True},
                       {"name": "impact_evidence", "passed": True}],
            "verified_refs": [{"excerpt": '"email": "victim@example.com"', "source": "observed",
                               "supports": "both", "step": 1,
                               "command": "curl -s https://api.example.com/v1/orders/1002"}],
        },
    }
    f.update(over)
    return f


class TestRuleLoading:
    def test_parses_hunters_files(self, rules, tmp_path):
        assert "Self-XSS" in rules.never_submit
        assert ("Open redirect", "OAuth code theft") in rules.chains
        assert rules.gotchas_for("idor")["minimum_proof"][0].startswith("Two hunter")
        assert rules.sources["validator"].endswith("validator.md")

    def test_fallback_when_files_missing(self, tmp_path):
        r = RuleSet.load(tmp_path / "nope.md", tmp_path / "nope2.md")
        assert r.never_submit  # built-in list
        assert "built-in" in r.sources["validator"]
        assert "not found" in r.sources["gotchas"]

    def test_matchers_follow_the_list(self, tmp_path):
        """A class missing from the hunter's list is not killed by Q7."""
        v = tmp_path / "v.md"
        v.write_text("## Never-Submit List\n\n```\nSelf-XSS\n```\n")
        r = RuleSet.load(v, tmp_path / "none")
        res = FindingValidator(r).validate(_finding(raw_title="Open redirect on /go"))
        assert not any(q.q == "Q7" and q.status != "pass" for q in res.questions)

    @pytest.mark.skipif(not VALIDATOR_PATH.is_file() or _find_gotchas() is None,
                        reason="hunter's Claude Code files not installed")
    def test_real_installed_files_load(self):
        r = RuleSet.load()
        assert len(r.never_submit) >= 10
        assert "idor / bola" in r.gotchas


class TestVerdicts:
    def test_best_outcome_is_ready_never_pass(self, validator, scope):
        res = validator.validate(_finding(), scope_policy=scope)
        assert res.verdict == Verdict.READY_FOR_VALIDATOR, res.to_dict()
        statuses = {q.q: q.status for q in res.questions}
        assert statuses["Q2"] == "human" and statuses["Q5"] == "human"
        assert any("Two hunter-controlled accounts" in h for h in res.human_checks)

    def test_lead_is_kill_q1(self, validator, scope):
        res = validator.validate(_finding(verification="lead"), scope_policy=scope)
        assert res.label == "KILL Q1"

    def test_agent_script_only_evidence_is_kill_q1(self, validator, scope):
        f = _finding()
        f["proof"]["verified_refs"][0]["source"] = "agent_script"
        assert validator.validate(f, scope_policy=scope).label == "KILL Q1"

    def test_out_of_scope_asset_is_kill_q3(self, validator, scope):
        res = validator.validate(_finding(asset="https://evil.org/x"), scope_policy=scope)
        assert res.label == "KILL Q3"

    def test_admin_only_is_kill_q4(self, validator, scope):
        res = validator.validate(_finding(privileges_required="admin"), scope_policy=scope)
        assert res.label == "KILL Q4"

    def test_idor_without_two_identities_is_kill_q6(self, validator, scope):
        res = validator.validate(_finding(victim_identity="user-a"), scope_policy=scope)
        assert res.label == "KILL Q6"

    def test_idor_victim_identifier_must_be_in_evidence(self, validator, scope):
        res = validator.validate(_finding(victim_identifier="someone-else@example.com"),
                                 scope_policy=scope)
        assert res.label == "KILL Q6"

    def test_sql_error_only_is_downgrade(self, validator, scope):
        f = _finding(raw_title="SQL injection in search", vuln_class="sqli",
                     attacker_identity="", victim_identity="")
        f["proof"]["verified_refs"][0]["excerpt"] = "You have an error in your SQL syntax"
        res = validator.validate(f, scope_policy=scope)
        assert res.verdict == Verdict.DOWNGRADE
        assert res.suggested_severity == "Medium"

    def test_self_xss_is_kill_q7(self, validator, scope):
        f = _finding(raw_title="Self-XSS in profile name", vuln_class="xss")
        assert validator.validate(f, scope_policy=scope).label == "KILL Q7"

    def test_open_redirect_alone_needs_chain(self, validator, scope):
        f = _finding(raw_title="Open redirect on /go", vuln_class="open redirect")
        res = validator.validate(f, scope_policy=scope)
        assert res.verdict == Verdict.CHAIN_REQUIRED
        assert "OAuth code theft" in res.reason

    def test_open_redirect_chained_with_confirmed_finding(self, validator, scope):
        f = _finding(raw_title="Open redirect on /go", vuln_class="open redirect",
                     chained_with=["OAuth code theft via redirect_uri"])
        res = validator.validate(f, scope_policy=scope,
                                 confirmed_titles=["OAuth code theft via redirect_uri"])
        assert next(q for q in res.questions if q.q == "Q7").status == "pass"

    def test_credentialed_cors_is_not_never_submit(self, validator, scope):
        f = _finding(raw_title="CORS origin reflection with credentials", vuln_class="cors",
                     attacker_identity="", victim_identity="")
        f["proof"]["verified_refs"][0]["excerpt"] = (
            "Access-Control-Allow-Origin: https://evil.org\nAccess-Control-Allow-Credentials: true")
        res = validator.validate(f, scope_policy=scope)
        assert res.verdict == Verdict.READY_FOR_VALIDATOR, res.to_dict()

    def test_cors_without_credentials_killed(self, validator, scope):
        f = _finding(raw_title="CORS wildcard", vuln_class="cors",
                     attacker_identity="", victim_identity="")
        f["proof"]["verified_refs"][0]["excerpt"] = "Access-Control-Allow-Origin: *"
        assert validator.validate(f, scope_policy=scope).verdict == Verdict.KILL

    def test_rate_limit_on_otp_is_not_killed(self, validator, scope):
        f = _finding(raw_title="Missing rate limit on OTP verification", vuln_class="",
                     attacker_identity="", victim_identity="")
        q7 = next(q for q in validator.validate(f, scope_policy=scope).questions if q.q == "Q7")
        assert q7.status == "pass"


class TestProgramRules:
    def test_excluded_class_is_kill_q2(self, validator, scope, tmp_path):
        p = tmp_path / "program.yaml"
        p.write_text("in_scope: ['*.example.com']\nexcluded_classes: [idor]\n")
        program = ProgramRules.from_file(str(p))
        res = validator.validate(_finding(), scope_policy=scope, program=program)
        assert res.label == "KILL Q2"

    def test_severity_cap_downgrades(self, validator, scope, tmp_path):
        p = tmp_path / "program.yaml"
        p.write_text("in_scope: ['*.example.com']\nseverity_caps: {idor: Medium}\n")
        program = ProgramRules.from_file(str(p))
        res = validator.validate(_finding(), scope_policy=scope, program=program)
        assert res.verdict == Verdict.DOWNGRADE and res.suggested_severity == "Medium"

    def test_plain_scope_file_has_no_program_rules(self, tmp_path):
        p = tmp_path / "scope.txt"
        p.write_text("*.example.com\n")
        assert ProgramRules.from_file(str(p)) is None


# ── Agent integration + handoff packet ───────────────────────────────────────


@pytest.fixture
def agent(tmp_path):
    from hackbot.modes.agent import AgentMode, AgentStep

    v = tmp_path / "validator.md"
    v.write_text(VALIDATOR_MD)
    g = tmp_path / "gotchas.md"
    g.write_text(GOTCHAS_MD)
    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    config.validation = ValidationConfig(handoff_dir=str(tmp_path / "out"),
                                         validator_path=str(v), gotchas_path=str(g))
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a._assessment_id = None
    a._rag_enabled = False
    a.target = "api.example.com"
    a.scope_policy = ScopePolicy(in_scope=["*.example.com"])
    out = '{"id": 1002, "email": "victim@example.com", "owner": "user-b"}'
    res = ToolResult(tool="curl", command="curl -s https://api.example.com/v1/orders/1002",
                     stdout=out, stderr="", return_code=0, duration=0.1, success=True)
    a.steps.append(AgentStep(step_num=1, action="execute", description="", tool_result=res))
    return a


ACTION = {
    "action": "finding", "title": "IDOR on orders", "severity": "High", "vuln_class": "idor",
    "behavior": "GET /v1/orders/1002 with user A's session returns user B's order",
    "boundary": "object-level authorization between customer accounts",
    "impact": "user A read user B's order and email victim@example.com",
    "evidence_refs": [{"step": 1, "excerpt": '"email": "victim@example.com"'}],
    "asset": "https://api.example.com/v1/orders/1002", "privileges_required": "user",
    "attacker_identity": "user-a", "victim_identity": "user-b",
    "victim_identifier": "victim@example.com",
}


def test_record_finding_runs_prevalidation(agent):
    msg = agent._record_finding(dict(ACTION))
    f = agent.findings[0]
    assert f.confirmed
    assert f.validation["verdict"] == "ready_for_validator"
    assert "**[Pre-validation]** READY_FOR_VALIDATOR" in msg


def test_handoff_packet(agent, tmp_path):
    shot = tmp_path / "burp.txt"
    shot.write_text("GET /v1/orders/1002\n\n" + '{"email": "victim@example.com"}')
    agent._record_finding(dict(ACTION))
    agent.attest_evidence(0, str(shot), "Burp repeater")
    path = agent.export_handoff(0)
    assert path.is_dir() and str(path).startswith(str(tmp_path / "out"))
    md = (path / "packet.md").read_text()
    assert "Proof gate:** CONFIRMED" in md
    assert "READY_FOR_VALIDATOR" in md
    assert '"email": "victim@example.com"' in md
    assert "Two hunter-controlled accounts" in md  # gotchas minimum proof as checklist
    assert (path / "evidence" / "step-1.txt").read_text().startswith("$ curl")
    assert (path / "recorded" / "burp.txt").is_file()
    data = json.loads((path / "finding.json").read_text())
    assert data["raw_title"] == "IDOR on orders"


def test_handoff_marks_unknown_fields(agent):
    act = dict(ACTION, privileges_required="", attacker_identity="", victim_identity="")
    agent._record_finding(act)
    md = (agent.export_handoff(0) / "packet.md").read_text()
    assert "Privileges required:** _not provided_" in md


def test_claude_code_command_exists():
    cmd = Path(__file__).resolve().parents[2] / ".claude" / "commands" / "hackbot-validate.md"
    if not cmd.exists():
        pytest.skip("HUNTIX workspace command not present (repo used standalone)")
    text = cmd.read_text()
    for name in ("validator", "ywh:write", "ywh:triage"):
        assert name in text
