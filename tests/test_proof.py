"""Tests for the proof gate (hackbot.core.proof) and its agent integration."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.engine import AIEngine
from hackbot.core.proof import (
    Observation,
    ProofGate,
    RecordedEvidence,
    Verification,
    detect_class,
)
from hackbot.core.runner import ToolResult
from hackbot.reporting import calculate_security_posture

IDOR_OUTPUT = (
    'HTTP/1.1 200 OK\n{"id": 1002, "email": "victim@example.com", "owner": "user-b"}'
)
IDOR_CMD = "curl -s -H 'Cookie: session=user-a' https://api.example.com/v1/orders/1002"


def _obs(output=IDOR_OUTPUT, cmd=IDOR_CMD, step=3):
    return Observation.from_command(step, cmd, output)


def _claim(**over):
    claim = dict(
        title="IDOR on /v1/orders/{id}",
        behavior="GET /v1/orders/1002 with user A's session returns order 1002 owned by user B",
        boundary="object-level authorization between two distinct customer accounts",
        impact="user A read user B's order including B's email address victim@example.com",
        evidence_refs=[{"step": 3, "excerpt": '"email": "victim@example.com"', "supports": "both"}],
        observations=[_obs()],
    )
    claim.update(over)
    return claim


class TestPillars:
    def test_fully_evidenced_finding_is_confirmed(self):
        r = ProofGate().evaluate(**_claim())
        assert r.verification == Verification.CONFIRMED, r.summary()
        assert r.verified_refs[0]["source"] == "observed"
        assert r.verified_refs[0]["step"] == 3

    @pytest.mark.parametrize("pillar", ["behavior", "boundary", "impact"])
    def test_missing_pillar_stays_lead(self, pillar):
        r = ProofGate().evaluate(**_claim(**{pillar: ""}))
        assert r.verification == Verification.LEAD
        assert any(pillar in m for m in r.missing)

    @pytest.mark.parametrize("impact", [
        "an attacker could read every customer's orders",
        "this may lead to account takeover",
        "potentially exposes PII of all users",
        "if an attacker guesses IDs they read orders",
    ])
    def test_speculative_impact_stays_lead(self, impact):
        r = ProofGate().evaluate(**_claim(impact=impact))
        assert r.verification == Verification.LEAD
        assert any("speculative" in m for m in r.missing)

    def test_impact_needs_its_own_supporting_evidence(self):
        refs = [{"excerpt": '"email": "victim@example.com"', "supports": "behavior"}]
        r = ProofGate().evaluate(**_claim(evidence_refs=refs))
        assert r.verification == Verification.LEAD
        assert any("supports the impact" in m for m in r.missing)


class TestEvidenceIntegrity:
    def test_fabricated_excerpt_rejected(self):
        refs = [{"excerpt": '"email": "admin@example.com", "role": "admin"'}]
        r = ProofGate().evaluate(**_claim(evidence_refs=refs))
        assert r.verification == Verification.LEAD
        assert any("not found" in m for m in r.missing)

    def test_one_fabricated_excerpt_among_real_ones_fails(self):
        refs = [{"excerpt": '"email": "victim@example.com"'}, {"excerpt": "card 4111 1111 1111"}]
        assert ProofGate().evaluate(**_claim(evidence_refs=refs)).verification == Verification.LEAD

    def test_no_evidence_refs(self):
        assert ProofGate().evaluate(**_claim(evidence_refs=[])).verification == Verification.LEAD

    def test_trivially_short_excerpt_rejected(self):
        r = ProofGate().evaluate(**_claim(evidence_refs=["200 OK"]))
        assert r.verification == Verification.LEAD

    def test_whitespace_differences_tolerated(self):
        refs = ['"email":   "victim@example.com",\n "owner"']
        assert ProofGate().evaluate(**_claim(evidence_refs=refs)).verification \
            == Verification.CONFIRMED

    @pytest.mark.parametrize("cmd", [
        "echo '\"email\": \"victim@example.com\"'",
        "printf '%s' victim",
        "cat notes.txt",
    ])
    def test_self_printing_tools_are_not_evidence(self, cmd):
        assert Observation.from_command(1, cmd, IDOR_OUTPUT) is None

    def test_literal_from_agent_script_is_not_evidence(self, tmp_path):
        script = tmp_path / "poc.py"
        script.write_text('print(\'"email": "victim@example.com"\')\n')
        obs = Observation.from_command(4, f"{sys.executable} {script}", IDOR_OUTPUT)
        r = ProofGate().evaluate(**_claim(observations=[obs]))
        assert r.verification == Verification.LEAD

    def test_literal_from_inline_code_is_not_evidence(self):
        cmd = "python3 -c \"print('\\\"email\\\": \\\"victim@example.com\\\"')\""
        obs = Observation.from_command(4, cmd, IDOR_OUTPUT)
        assert ProofGate().evaluate(**_claim(observations=[obs])).verification == Verification.LEAD


    def test_agent_script_output_alone_cannot_confirm(self, tmp_path):
        """Even when the excerpt is not a literal in the script, agent-authored
        code can assemble it — it needs independent corroboration."""
        script = tmp_path / "poc.py"
        script.write_text("print('\"em' + 'ail\": \"victim@example.com\"')\n")
        obs = Observation.from_command(4, f"python3 {script}", IDOR_OUTPUT)
        r = ProofGate().evaluate(**_claim(observations=[obs]))
        assert r.verification == Verification.LEAD
        assert any("agent-written code" in m for m in r.missing)

    def test_agent_script_plus_direct_request_confirms(self, tmp_path):
        script = tmp_path / "poc.py"
        script.write_text("import requests\n")
        authored = Observation.from_command(4, f"python3 {script}", IDOR_OUTPUT)
        r = ProofGate().evaluate(**_claim(observations=[authored, _obs()]))
        assert r.verification == Verification.CONFIRMED, r.summary()

    def test_independent_output_preferred_without_step(self, tmp_path):
        script = tmp_path / "poc.py"
        script.write_text("import requests\n")
        authored = Observation.from_command(1, f"python3 {script}", IDOR_OUTPUT)
        refs = ['"email": "victim@example.com"']
        r = ProofGate().evaluate(**_claim(observations=[authored, _obs()], evidence_refs=refs))
        assert r.verification == Verification.CONFIRMED, r.summary()
        assert r.verified_refs[0]["source"] == "observed"


class TestRecordedEvidence:
    def test_xss_needs_recorded_proof(self):
        out = "<p>Hello <script>alert(document.domain)</script></p>"
        obs = Observation.from_command(2, "curl -s 'https://www.example.com/q?s=x'", out)
        claim = _claim(
            title="Reflected XSS in search",
            behavior="the s parameter is reflected unencoded inside the HTML body",
            boundary="same-origin policy of www.example.com",
            impact="attacker-supplied script ran in the www.example.com origin",
            evidence_refs=["<script>alert(document.domain)</script>"],
            observations=[obs],
        )
        r = ProofGate().evaluate(**claim)
        assert r.verification == Verification.LEAD
        assert any("browser" in m for m in r.missing)

    def test_xss_with_attested_screenshot_confirms(self, tmp_path):
        shot = tmp_path / "alert.png"
        shot.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00fake")
        out = "<p>Hello <script>alert(document.domain)</script></p>"
        obs = Observation.from_command(2, "curl -s 'https://www.example.com/q?s=x'", out)
        r = ProofGate().evaluate(**_claim(
            title="Reflected XSS in search",
            behavior="the s parameter is reflected unencoded inside the HTML body",
            boundary="same-origin policy of www.example.com",
            impact="attacker-supplied script ran in the www.example.com origin",
            evidence_refs=["<script>alert(document.domain)</script>"],
            observations=[obs],
            recorded=[RecordedEvidence.attest(str(shot), "alert fired in Chrome")],
        ))
        assert r.verification == Verification.CONFIRMED, r.summary()

    def test_tampered_recording_fails(self, tmp_path):
        burp = tmp_path / "req.txt"
        burp.write_text("HTTP/1.1 200 OK\nbalance: 1000000\n")
        rec = RecordedEvidence.attest(str(burp))
        burp.write_text("HTTP/1.1 200 OK\nbalance: 9999999\n")
        r = ProofGate().evaluate(**_claim(recorded=[rec]))
        assert r.verification == Verification.LEAD
        assert any("changed" in m for m in r.missing)

    def test_text_recording_can_back_excerpts(self, tmp_path):
        """State-changing proof done once by the human, recorded in Burp, then attested."""
        burp = tmp_path / "delete.txt"
        burp.write_text("DELETE /v1/orders/1002 HTTP/1.1\n\nHTTP/1.1 204 No Content\n"
                        "X-Deleted-Order: 1002 owner=user-b\n")
        r = ProofGate().evaluate(**_claim(
            impact="user A deleted user B's order 1002",
            evidence_refs=["X-Deleted-Order: 1002 owner=user-b"],
            observations=[],
            recorded=[RecordedEvidence.attest(str(burp))],
        ))
        assert r.verification == Verification.CONFIRMED, r.summary()
        assert r.verified_refs[0]["source"] == "recorded"


def test_detect_class():
    assert detect_class("Stored Cross-Site Scripting in profile") == "xss"
    assert detect_class("Thing", vuln_class="CSRF") == "csrf"
    assert detect_class("IDOR on orders") == ""


# ── Agent integration ────────────────────────────────────────────────────────


@pytest.fixture
def agent():
    from hackbot.modes.agent import AgentMode, AgentStep

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    config.agent = AgentConfig(allowed_tools=["curl"], safe_mode=True)
    config.scope = ScopeConfig(audit_log=False)
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    a._assessment_id = None
    a._rag_enabled = False
    a.target = "api.example.com"
    result = ToolResult(tool="curl", command=IDOR_CMD, stdout=IDOR_OUTPUT, stderr="",
                        return_code=0, duration=0.2, success=True)
    a.steps.append(AgentStep(step_num=1, action="execute", description="fetch", tool_result=result))
    blocked = ToolResult(tool="curl", command="curl https://evil.org", stdout="",
                         stderr="BLOCKED: OUT OF SCOPE: evil.org", return_code=-1,
                         duration=0, success=False)
    a.steps.append(AgentStep(step_num=2, action="execute", description="x", tool_result=blocked))
    return a


def _action(**over):
    act = {
        "action": "finding", "title": "IDOR on orders", "severity": "High",
        "behavior": "GET /v1/orders/1002 with user A's session returns user B's order",
        "boundary": "object-level authorization between customer accounts",
        "impact": "user A read user B's order and email victim@example.com",
        "evidence_refs": [{"step": 1, "excerpt": '"email": "victim@example.com"'}],
    }
    act.update(over)
    return act


class TestAgentIntegration:
    def test_confirmed_finding(self, agent):
        msg = agent._record_finding(_action())
        f = agent.findings[0]
        assert f.confirmed, f.proof
        assert "CONFIRMED" in msg
        assert f.to_dict()["title"] == "IDOR on orders"

    def test_unproven_finding_is_lead_with_feedback(self, agent):
        msg = agent._record_finding(_action(impact="could expose all orders"))
        f = agent.findings[0]
        assert not f.confirmed
        assert "UNVERIFIED LEAD" in msg and "speculative" in msg
        assert f.to_dict()["title"].startswith("[UNVERIFIED LEAD]")

    def test_blocked_command_output_is_not_evidence(self, agent):
        agent._record_finding(_action(evidence_refs=["OUT OF SCOPE: evil.org"]))
        assert not agent.findings[0].confirmed

    def test_resubmission_upgrades_lead_in_place(self, agent):
        agent._record_finding(_action(evidence_refs=[]))
        assert not agent.findings[0].confirmed
        agent._record_finding(_action())
        assert len(agent.findings) == 1
        assert agent.findings[0].confirmed

    def test_attest_recorded_evidence(self, agent, tmp_path):
        burp = tmp_path / "proof.txt"
        burp.write_text('{"id": 1002, "email": "victim@example.com"}')
        agent._record_finding(_action(evidence_refs=['"id": 1002, "email"'], ))
        # excerpt exists only in the recording, not in captured output
        agent.findings[0].evidence_refs = ['{"id": 1002, "email": "victim@example.com"}']
        agent.evaluate_finding(agent.findings[0])
        assert not agent.findings[0].confirmed
        f = agent.attest_evidence(0, str(burp), "Burp repeater")
        assert f.confirmed, f.proof

    def test_summary_separates_leads(self, agent):
        agent._record_finding(_action())
        agent._record_finding(_action(title="Possible SQLi", impact="", evidence_refs=[]))
        text = agent.get_findings_summary()
        assert "**Confirmed: 1** | Unverified leads: 1" in text
        assert "NOT confirmed vulnerabilities" in text
        assert "Missing proof" in text

    def test_posture_ignores_leads(self, agent):
        agent._record_finding(_action(title="Lead", impact="", evidence_refs=[],
                                      severity="Critical"))
        posture = calculate_security_posture([f.to_dict() for f in agent.findings])
        assert posture["score"] == 100
        assert posture["counts"]["Critical"] == 0

    def test_replay_reproduces(self, agent):
        agent._record_finding(_action())
        agent.runner.execute = MagicMock(return_value=ToolResult(
            tool="curl", command=IDOR_CMD, stdout=IDOR_OUTPUT, stderr="",
            return_code=0, duration=0.1, success=True))
        assert agent.reproduce_finding(0)["reproduced"]
        assert agent.findings[0].confirmed

    def test_failed_replay_demotes_to_lead(self, agent):
        agent._record_finding(_action())
        agent.runner.execute = MagicMock(return_value=ToolResult(
            tool="curl", command=IDOR_CMD, stdout='{"error": "forbidden"}', stderr="",
            return_code=0, duration=0.1, success=True))
        assert not agent.reproduce_finding(0)["reproduced"]
        assert not agent.findings[0].confirmed

    def test_replay_goes_through_gates(self, agent, monkeypatch):
        """A state-changing evidence command is not replayed without a human yes."""
        calls = []
        monkeypatch.setattr("hackbot.core.runner.subprocess.Popen",
                            lambda *a, **k: calls.append(a) or None)
        post_cmd = "curl -s -X DELETE https://api.example.com/v1/orders/1002"
        res = ToolResult(tool="curl", command=post_cmd, stdout="deleted order 1002 owner user-b",
                         stderr="", return_code=0, duration=0.1, success=True)
        from hackbot.modes.agent import AgentStep
        agent.steps.append(AgentStep(step_num=3, action="execute", description="d",
                                     tool_result=res))
        agent._record_finding(_action(title="BOLA delete", impact="user A deleted B's order",
                                      evidence_refs=["deleted order 1002 owner user-b"]))
        out = agent.reproduce_finding(0)
        assert out["results"][0]["blocked"]
        assert calls == []


def test_vulndb_keeps_one_record_from_lead_to_confirmed(tmp_path):
    from hackbot.core.vulndb import VulnDB

    db = VulnDB(db_path=tmp_path / "v.db")
    aid = db.create_assessment(target="api.example.com")
    lead = {"title": "[UNVERIFIED LEAD] IDOR", "raw_title": "IDOR", "severity": "High",
            "tags": ["verification:lead"]}
    confirmed = {"title": "IDOR", "raw_title": "IDOR", "severity": "High",
                 "tags": ["verification:confirmed"]}
    first = db.add_finding(aid, lead, target="api.example.com")
    second = db.add_finding(aid, confirmed, target="api.example.com")
    assert first == second
    rec = db.get_finding(first)
    assert rec.title == "IDOR"
    assert "verification:confirmed" in rec.tags
