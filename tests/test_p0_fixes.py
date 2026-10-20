"""Regression tests for the defects found in benchmark run juice-shop-blind-1 (D1–D6)."""

from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityVault
from hackbot.core.runner import ToolResult
from hackbot.core.scope import ScopePolicy
from hackbot.core.validation import FindingValidator, RuleSet, Verdict
from hackbot.modes.agent import Severity, normalize_asset, parse_severity

VALIDATOR_MD = """## Never-Submit List

```
SSRF DNS-only
Self-XSS
```

## Conditionally Valid (chain required)

```
SSRF DNS-only → + internal data → CHAIN REQUIRED
```
"""


@pytest.fixture
def agent(tmp_path):
    from hackbot.modes.agent import AgentMode, AgentStep

    v = tmp_path / "validator.md"
    v.write_text(VALIDATOR_MD)
    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    config.validation.validator_path = str(v)
    config.validation.gotchas_path = str(tmp_path / "none")
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a._assessment_id, a._rag_enabled, a.target = None, False, "127.0.0.1"
    a.scope_policy = ScopePolicy(in_scope=["http://127.0.0.1:3000"])
    a.identity_vault = IdentityVault.from_dict({"identities": {
        "hunter1": {"role": "customer", "markers": ["hunter1@lab.test"]},
        "hunter2": {"role": "customer", "markers": ["hunter2@lab.test"]}}})
    outputs = {
        1: '{"id":26,"email":"hunter2@lab.test","role":"customer"}',
        2: '{"status":"success","data":{"orderConfirmation":"ab12-cd34"}}',
        3: '{"orderId":"ab12-cd34","totalPrice":-19.9,"paymentId":null}',
        4: "User-agent: *\nDisallow: /ftp",
        5: '"name":"3.44.2","description":"huntix-marker"',
    }
    for n, out in outputs.items():
        res = ToolResult(tool="curl", command=f"curl -s http://127.0.0.1:3000/x{n}", stdout=out,
                         stderr="", return_code=0, duration=0.1, success=True)
        a.steps.append(AgentStep(step_num=n, action="execute", description="", tool_result=res))
    return a


def _act(**over):
    act = {"action": "finding", "title": "t", "severity": "High", "vuln_class": "bola",
           "behavior": "hunter1's token reading /api/Users/26 returns hunter2's record",
           "boundary": "object-level authorization between two accounts",
           "impact": "hunter1 read hunter2's account record",
           "evidence_refs": [{"step": 1, "excerpt": '"email":"hunter2@lab.test"'}],
           "attacker_identity": "hunter1", "victim_identity": "hunter2",
           "asset": "http://127.0.0.1:3000/api/Users/26", "privileges_required": "user"}
    act.update(over)
    return act


# D1 ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,sev", [
    ("critical", Severity.CRITICAL), ("CRITICAL", Severity.CRITICAL), ("High", Severity.HIGH),
    ("moderate", Severity.MEDIUM), ("low", Severity.LOW), ("informational", Severity.INFO),
    ("P2", Severity.HIGH), ("banana", Severity.INFO), (None, Severity.INFO),
])
def test_d1_parse_severity(raw, sev):
    assert parse_severity(raw) is sev


def test_d1_record_keeps_lowercase_severity(agent):
    agent._record_finding(_act(severity="critical"))
    assert agent.findings[0].severity is Severity.CRITICAL


# D2 ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,url", [
    ("GET http://127.0.0.1:3000/rest/products/search?q=", "http://127.0.0.1:3000/rest/products/search?q="),
    ("POST http://127.0.0.1:3000/api/Users (registration)", "http://127.0.0.1:3000/api/Users"),
    ("http://127.0.0.1:3000/ftp.", "http://127.0.0.1:3000/ftp"),
    ("/relative/path", "/relative/path"),
])
def test_d2_normalize_asset(raw, url):
    assert normalize_asset(raw) == url


def test_d2_method_prefixed_asset_passes_q3(agent):
    agent._record_finding(_act(asset="GET http://127.0.0.1:3000/api/Users/26"))
    q3 = next(q for q in agent.findings[0].validation["questions"] if q["q"] == "Q3")
    assert q3["status"] == "pass", q3
    assert agent.findings[0].asset == "http://127.0.0.1:3000/api/Users/26"


# D3 ─────────────────────────────────────────────────────────────────────────
def test_d3_free_text_identifier_with_vault_marker_in_evidence(agent):
    agent._record_finding(_act(victim_identifier="Users.id=26"))
    q6 = next(q for q in agent.findings[0].validation["questions"] if q["q"] == "Q6")
    assert q6["status"] == "pass", q6


def test_d3_still_fails_when_no_victim_data_in_evidence(agent):
    agent._record_finding(_act(
        victim_identifier="Users.id=26",
        evidence_refs=[{"step": 2, "excerpt": '"orderConfirmation":"ab12-cd34"'}]))
    q6 = next(q for q in agent.findings[0].validation["questions"] if q["q"] == "Q6")
    assert q6["status"] == "fail"


# D4 ─────────────────────────────────────────────────────────────────────────
@pytest.fixture
def validator(tmp_path):
    v = tmp_path / "validator.md"
    v.write_text(VALIDATOR_MD)
    return FindingValidator(RuleSet.load(v, tmp_path / "none"))


def _ssrf(title, excerpt):
    return {"raw_title": title, "vuln_class": "ssrf", "severity": "High",
            "verification": "confirmed", "privileges_required": "user",
            "impact": "the server fetched an attacker-chosen loopback URL and returned its body",
            "proof": {"checks": [{"name": "impact", "passed": True},
                                 {"name": "impact_evidence", "passed": True}],
                      "verified_refs": [{"excerpt": excerpt, "source": "observed",
                                         "supports": "both", "step": 4, "command": ""}]}}


def test_d4_full_read_ssrf_is_not_dns_only(validator):
    res = validator.validate(_ssrf("Full-read SSRF via profile image URL", "User-agent: *"))
    assert next(q for q in res.questions if q.q == "Q7").status == "pass"
    assert res.verdict == Verdict.READY_FOR_VALIDATOR, res.to_dict()


def test_d4_dns_only_ssrf_is_still_not_ready(validator):
    """validator.md order: Q6 (DNS-only → severity reduction) before Q7 (chain)."""
    res = validator.validate(_ssrf("Blind SSRF confirmed by DNS callback", "dns interaction from"))
    assert res.verdict in (Verdict.DOWNGRADE, Verdict.CHAIN_REQUIRED)
    assert "dns" in res.reason.lower()


# D5 ─────────────────────────────────────────────────────────────────────────
LOGIC = dict(vuln_class="business_logic", attacker_identity="", victim_identity="",
             asset="http://127.0.0.1:3000/rest/basket/6/checkout",
             behavior="checkout accepted a basket with a negative quantity and no payment",
             boundary="order totals must be non-negative and paid",
             impact="an order with a negative total was placed without payment")


def test_d5_refiled_lead_is_upgraded_not_duplicated(agent):
    agent._record_finding(_act(title="Negative quantities accepted", **LOGIC, evidence_refs=[
        {"step": 2, "excerpt": "mis-quoted text that is not in the output"},
        {"step": 3, "excerpt": '"totalPrice":-19.9'}]))
    assert not agent.findings[0].confirmed
    agent._record_finding(_act(title="Checkout accepts negative-total orders", **LOGIC,
                               evidence_refs=[
                                   {"step": 2, "excerpt": '"orderConfirmation":"ab12-cd34"'},
                                   {"step": 3, "excerpt": '"totalPrice":-19.9'}]))
    assert len(agent.findings) == 1
    assert agent.findings[0].title == "Negative quantities accepted"


def test_d5_different_evidence_stays_separate(agent):
    agent._record_finding(_act(title="A", evidence_refs=[
        {"step": 1, "excerpt": '"email":"hunter2@lab.test"'},
        {"step": 5, "excerpt": '"description":"huntix-marker"'}]))
    agent._record_finding(_act(title="B", **LOGIC, evidence_refs=[
        {"step": 2, "excerpt": '"orderConfirmation":"ab12-cd34"'},
        {"step": 3, "excerpt": '"totalPrice":-19.9'}]))
    assert len(agent.findings) == 2


def test_d5_single_shared_step_is_not_enough(agent):
    agent._record_finding(_act(title="A", evidence_refs=[
        {"step": 1, "excerpt": '"email":"hunter2@lab.test"'},
        {"step": 5, "excerpt": '"description":"huntix-marker"'}]))
    agent._record_finding(_act(title="B", asset="http://127.0.0.1:3000/robots.txt",
                               evidence_refs=[
                                   {"step": 1, "excerpt": '"email":"hunter2@lab.test"'},
                                   {"step": 4, "excerpt": "User-agent: *"}]))
    assert len(agent.findings) == 2


# D6 ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("impact,excerpt,downgrade", [
    ("the server can reach cloud metadata and internal services", "User-agent: *", True),
    ("the server returned instance metadata", "ami-id\ninstance-id i-123", False),
    ("leading to full data compromise", '"name":"3.44.2"', True),
    ("enabling credential stuffing on other services", '"email":"hunter2@lab.test"', True),
    ("hunter1 read hunter2's account record", '"email":"hunter2@lab.test"', False),
])
def test_d6_overclaimed_impact_is_downgraded(validator, impact, excerpt, downgrade):
    f = _ssrf("Full-read SSRF via profile image URL", excerpt)
    f["impact"] = impact
    res = validator.validate(f)
    assert (res.verdict == Verdict.DOWNGRADE) is downgrade, res.to_dict()
    if downgrade:
        assert "does not show" in res.reason


def test_d6_rce_claim_needs_command_output(validator):
    f = _ssrf("Command injection in export", "uid=1000(app) gid=1000(app)")
    f.update(vuln_class="command injection", impact="remote code execution as the app user")
    assert validator.validate(f).verdict == Verdict.READY_FOR_VALIDATOR
    f["proof"]["verified_refs"][0]["excerpt"] = "export finished"
    assert validator.validate(f).verdict == Verdict.DOWNGRADE
