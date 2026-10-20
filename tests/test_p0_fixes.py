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


# D7 ─────────────────────────────────────────────────────────────────────────
def _vertical(excerpt):
    return {"raw_title": "Mass assignment of role at self-registration grants admin",
            "vuln_class": "mass_assignment / privilege escalation", "severity": "Critical",
            "verification": "confirmed", "privileges_required": "none",
            "attacker_identity": "anonymous", "victim_identity": "",
            "impact": "an anonymous visitor created an account whose stored role is admin",
            "proof": {"checks": [{"name": "impact", "passed": True},
                                 {"name": "impact_evidence", "passed": True}],
                      "verified_refs": [{"excerpt": excerpt, "source": "observed",
                                         "supports": "both", "step": 4, "command": ""}]}}


def test_d7_vertical_escalation_needs_no_victim(validator):
    res = validator.validate(_vertical('"email":"hunter2@lab.test","role":"admin"'))
    q6 = next(q for q in res.questions if q.q == "Q6")
    assert q6.status == "pass", q6


def test_d7_vertical_escalation_needs_elevated_role_in_evidence(validator):
    res = validator.validate(_vertical('"email":"hunter2@lab.test","role":"customer"'))
    q6 = next(q for q in res.questions if q.q == "Q6")
    assert q6.status == "fail" and "elevated" in q6.detail


def test_d7_horizontal_still_needs_two_identities(agent):
    agent._record_finding(_act(victim_identity="hunter1"))  # attacker == victim
    q6 = next(q for q in agent.findings[0].validation["questions"] if q["q"] == "Q6")
    assert q6["status"] == "fail"


# D8 ─────────────────────────────────────────────────────────────────────────
@pytest.fixture
def logic_agent(agent):
    from hackbot.modes.agent import AgentStep

    agent.steps.clear()
    runs = [
        (1, "curl -s -X PUT http://127.0.0.1:3000/api/BasketItems/9", '"id":9,"quantity":-5'),
        (2, "curl -s -X POST http://127.0.0.1:3000/rest/basket/6/checkout",
         '{"orderConfirmation":"87b1-1a1c"}'),
        (3, "curl -s -X GET http://127.0.0.1:3000/rest/order-history",
         '{"orderId":"87b1-1a1c","totalPrice":-9.95,"paymentId":null}'),
    ]
    for n, cmd, out in runs:
        res = ToolResult(tool="curl", command=cmd, stdout=out, stderr="", return_code=0,
                         duration=0.1, success=True)
        agent.steps.append(AgentStep(step_num=n, action="execute", description="",
                                     tool_result=res))
    return agent


LOGIC_ACT = dict(title="Negative quantities give negative-total orders", severity="High",
                 attacker_identity="hunter2", victim_identity="",
                 asset="http://127.0.0.1:3000/rest/basket/6/checkout",
                 behavior="a negative quantity was stored and checkout placed the order",
                 boundary="order totals must be non-negative and paid",
                 impact="an order with total -9.95 and no payment was persisted")


@pytest.mark.parametrize("vclass", ["business logic / improper input validation",
                                    "price_manipulation", "payment_bypass"])
def test_d8_end_state_readback_confirms_regardless_of_wording(logic_agent, vclass):
    logic_agent._record_finding(_act(**LOGIC_ACT, vuln_class=vclass, evidence_refs=[
        {"step": 1, "excerpt": '"quantity":-5', "supports": "behavior"},
        {"step": 3, "excerpt": '"totalPrice":-9.95', "supports": "impact"}]))
    f = logic_agent.findings[0]
    assert f.confirmed, f.proof
    rec = next(c for c in f.proof["checks"] if c["name"] == "recorded_proof")
    assert "read back by a separate GET (step 3)" in rec["detail"]


def test_d8_without_a_later_read_it_stays_a_lead(logic_agent):
    logic_agent._record_finding(_act(**LOGIC_ACT, vuln_class="business logic", evidence_refs=[
        {"step": 1, "excerpt": '"quantity":-5', "supports": "behavior"},
        {"step": 2, "excerpt": '"orderConfirmation":"87b1-1a1c"', "supports": "impact"}]))
    assert not logic_agent.findings[0].confirmed


def test_d8_xss_still_needs_a_recording(logic_agent):
    logic_agent._record_finding(_act(**LOGIC_ACT, vuln_class="stored xss", evidence_refs=[
        {"step": 1, "excerpt": '"quantity":-5'}, {"step": 3, "excerpt": '"totalPrice":-9.95'}]))
    assert not logic_agent.findings[0].confirmed


# D9 ─────────────────────────────────────────────────────────────────────────
def test_d9_learn_user_id_from_own_response():
    v = IdentityVault.from_dict({"identities": {"hunter2": {"markers": ["hunter2@lab.test"]}}})
    learned = v.learn_from_response(
        "hunter2", '{"user": {"id": 26, "email": "hunter2@lab.test", "role": "customer"}}')
    assert '"UserId":26' in learned
    assert '"id":26' not in v.get("hunter2").markers  # too generic, never learned
    assert v.learn_from_response("hunter2", '{"user": {"id": 26}}') == []  # no email: no link
    assert v.learn_from_response("hunter2", "not json") == []


def test_d9_numeric_id_in_evidence_links_the_victim(agent):
    agent.identity_vault.learn_from_response(
        "hunter2", '{"user": {"id": 26, "email": "hunter2@lab.test"}}')
    from hackbot.modes.agent import AgentStep

    res = ToolResult(tool="curl", command="curl -s http://127.0.0.1:3000/rest/basket/6",
                     stdout='{"data":{"id":6,"coupon":null,"UserId":26}}', stderr="",
                     return_code=0, duration=0.1, success=True)
    agent.steps.append(AgentStep(step_num=9, action="execute", description="", tool_result=res))
    agent._record_finding(_act(title="Basket IDOR", victim_identifier="basket 6 (UserId 26)",
                               asset="http://127.0.0.1:3000/rest/basket/6",
                               evidence_refs=[{"step": 9,
                                               "excerpt": '"id":6,"coupon":null,"UserId":26'}]))
    q6 = next(q for q in agent.findings[0].validation["questions"] if q["q"] == "Q6")
    assert q6["status"] == "pass", q6


def test_d9_mcp_session_learns_markers(tmp_path, monkeypatch):
    import json as _json

    from hackbot.mcp_server import HuntSession

    scope = tmp_path / "scope.yaml"
    scope.write_text("in_scope: ['http://127.0.0.1:3000']\n")

    class P:
        returncode = 0
        stdout = None

        def __init__(self, *a, **k):
            pass

        def communicate(self, input=None, timeout=None):
            return ("HTTP/1.1 200 OK\r\n\r\n" + _json.dumps(
                {"user": {"id": 25, "email": "hunter1@lab.test"}}), "")

    monkeypatch.setattr("hackbot.core.runner.subprocess.Popen", P)
    s = HuntSession(str(scope), run_dir=str(tmp_path / "run"), lab_mode=True)
    s.register_identity("hunter1", bearer="tok-" + "z" * 30, markers=["hunter1@lab.test"])
    out = s.http_request("GET", "http://127.0.0.1:3000/rest/user/whoami", identity="hunter1")
    assert '"UserId":25' in out["learned_markers"]


# D10–D14 (blind fixture 1) ──────────────────────────────────────────────────
def _confirmed(title, vclass, excerpt, **over):
    f = {"raw_title": title, "vuln_class": vclass, "severity": "High",
         "verification": "confirmed", "privileges_required": "user",
         "impact": "shown in the excerpt", "attacker_identity": "alice", "victim_identity": "",
         "proof": {"checks": [{"name": "impact", "passed": True},
                              {"name": "impact_evidence", "passed": True}],
                   "verified_refs": [{"excerpt": excerpt, "source": "observed",
                                      "supports": "both", "step": 1, "command": ""}]}}
    f.update(over)
    return f


@pytest.mark.parametrize("excerpt,ok", [
    ('"role":"tenant_admin","tenant":"acme"', True),
    ('"role": "org-owner"', True),
    ('"roles": ["super_user"]', True),
    ('"isAdmin": true', True),
    ('"role":"member","tenant":"acme"', False),
])
def test_d10_elevated_role_by_meaning(validator, excerpt, ok):
    res = validator.validate(_confirmed("Mass assignment lets a member self-promote",
                                        "mass assignment / privilege escalation", excerpt))
    assert (next(q for q in res.questions if q.q == "Q6").status == "pass") is ok


def test_d11_internal_hostname_reach_is_not_overclaim(validator):
    f = _confirmed("SSRF in logo import", "ssrf", '"note": "INTERNAL-ONLY PW-INV-3f9a1c"',
                   impact="the server fetched an internal-only service and returned its body")
    f["proof"]["verified_refs"][0]["command"] = (
        "curl -s -X POST --data-raw '{\"url\": \"http://inventory-svc:8080/health\"}' "
        "http://127.0.0.1:4000/api/v1/branding/logo-import")
    assert validator.validate(f).verdict == Verdict.READY_FOR_VALIDATOR


def test_d11_public_host_does_not_count_as_internal(validator):
    f = _confirmed("SSRF in logo import", "ssrf", '"ok": true',
                   impact="the server reaches internal network services")
    f["proof"]["verified_refs"][0]["command"] = (
        "curl -s -X POST --data-raw '{\"url\": \"https://carrier.example/x\"}' "
        "http://127.0.0.1:4000/api/v1/branding/logo-import")
    assert validator.validate(f).verdict == Verdict.DOWNGRADE


def test_d12_control_step_404_does_not_make_a_soft_404():
    from hackbot.core.fp_filter import FalsePositiveClassifier

    finding = {"raw_title": "Path traversal in document download", "vuln_class": "traversal",
               "proof": {"verified_refs": [
                   {"excerpt": "Welcome to Parcelwise, Globex team.", "step": 2},
                   {"excerpt": '{"error":"not found"}', "step": 3}]}}
    outs = {2: {"command": "curl -s -i x", "output":
                "HTTP/1.1 200 OK\r\n\r\nWelcome to Parcelwise, Globex team."},
            3: {"command": "curl -s -i y", "output":
                'HTTP/1.1 404 NOT FOUND\r\n\r\n{"error":"not found"}'}}
    r = FalsePositiveClassifier().classify(finding, outs)
    assert "SOFT_404" not in [s["code"] for s in r["signals"]]
    outs[2]["output"] = "HTTP/1.1 200 OK\r\n\r\n<h1>Page not found</h1>"
    r = FalsePositiveClassifier().classify(finding, outs)
    assert "SOFT_404" in [s["code"] for s in r["signals"]]


@pytest.mark.parametrize("excerpt,ok", [
    ('{"email":"owner@globex.parcel","role":"tenant_admin"}', True),
    ('{"email":"hunter1@lab.test","role":"member"}', False),  # only the attacker's own data
    ('{"exported": true}', False),
])
def test_d13_bfla_without_victim_identity(validator, excerpt, ok):
    res = validator.validate(_confirmed(
        "Admin-only member export accessible to ordinary members",
        "broken function-level authorization (BFLA)", excerpt,
        attacker_markers=["hunter1@lab.test"]))
    assert (next(q for q in res.questions if q.q == "Q6").status == "pass") is ok


@pytest.mark.parametrize("act,expected", [
    ({"vuln_class": "SQL injection"}, "input_handling"),
    ({"vuln_class": "OS command injection"}, "input_handling"),
    ({"vuln_class": "Path traversal / arbitrary file read"}, "input_handling"),
    ({"vuln_class": "Broken function-level authorization (BFLA)"}, "function_level"),
    ({"vuln_class": "BOLA / IDOR", "victim_identity": "hunter2"}, "object_level"),
    ({"vuln_class": "business logic", "title": "promo reuse"}, "business_logic"),
    ({"vuln_class": "auth bypass", "attacker_identity": "anonymous"}, "authentication"),
])
def test_d14_boundary_type_inferred_for_manual_findings(act, expected):
    from hackbot.core.boundaries import infer_boundary_type

    assert infer_boundary_type(act, None) == expected


def test_d14_cross_tenant_manual_finding_gets_tenants(agent):
    agent.identity_vault = IdentityVault.from_dict({"identities": {
        "hunter1": {"tenant": "acme", "markers": ["hunter1@lab.test"]},
        "hunter2": {"tenant": "globex", "markers": ["hunter2@lab.test"]}}})
    agent._record_finding(_act(title="Invoice IDOR"))
    f = agent.findings[0]
    assert f.boundary_type == "tenant_isolation"
    assert (f.attacker_tenant, f.victim_tenant) == ("acme", "globex")
    assert f.title == "Invoice IDOR"  # hunter's text untouched
