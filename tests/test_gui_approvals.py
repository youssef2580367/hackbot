"""Tests for the GUI human-approval queue and finding review UI."""

import re
import threading
import time
from pathlib import Path

import pytest

from hackbot.core.runner import ToolRunner
from hackbot.core.scope import ScopePolicy
from hackbot.gui.approvals import ApprovalQueue

TEMPLATE = Path(__file__).resolve().parents[1] / "hackbot" / "gui" / "templates" / "index.html"


def _wait_pending(q, n=1, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if len(q.pending()) >= n:
            return q.pending()
        time.sleep(0.01)
    raise AssertionError("no pending approval appeared")


class TestQueue:
    def _ask_in_thread(self, q, out):
        t = threading.Thread(target=lambda: out.append(q.request("cmd", "why")))
        t.start()
        return t

    def test_approve(self):
        q, out = ApprovalQueue(timeout=2), []
        t = self._ask_in_thread(q, out)
        item = _wait_pending(q)[0]
        assert q.decide(item["id"], True)
        t.join(2)
        assert out == [True]
        assert q.pending() == []
        assert q.history()[-1]["decision"] is True

    def test_deny(self):
        q, out = ApprovalQueue(timeout=2), []
        t = self._ask_in_thread(q, out)
        assert q.decide(_wait_pending(q)[0]["id"], False)
        t.join(2)
        assert out == [False]

    def test_timeout_is_deny(self):
        q = ApprovalQueue(timeout=0.05)
        assert q.request("cmd", "why") is False
        assert q.history()[-1]["decision"] is False

    def test_unknown_or_repeated_decision(self):
        q, out = ApprovalQueue(timeout=2), []
        assert not q.decide(42, True)
        t = self._ask_in_thread(q, out)
        item = _wait_pending(q)[0]
        assert q.decide(item["id"], False)
        assert not q.decide(item["id"], True)  # cannot flip a decision
        t.join(2)
        assert out == [False]


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


class TestRunnerThroughGui:
    def test_gated_command_waits_for_gui_decision(self, fake_popen):
        from hackbot.gui import app as gui

        q = ApprovalQueue(timeout=2)
        gui._state["approvals"] = q
        runner = ToolRunner(allowed_tools=["curl"], safe_mode=True, auto_confirm=True,
                            on_confirm=lambda c, r: True,  # GUI-style auto_confirm wiring
                            on_approve=q.request,
                            scope_policy=ScopePolicy(in_scope=["api.example.com"]))
        out = []
        t = threading.Thread(target=lambda: out.append(
            runner.execute("curl -X DELETE https://api.example.com/v1/items/9")))
        t.start()
        pending = _wait_pending(q)
        assert fake_popen.calls == []  # paused, not executed
        assert "state_change" in pending[0]["reason"]

        client = gui.app.test_client()
        assert client.get("/api/approvals").get_json()["pending"][0]["id"] == pending[0]["id"]
        assert client.post(f"/api/approvals/{pending[0]['id']}",
                           json={"approve": "yes"}).status_code == 400
        assert client.post(f"/api/approvals/{pending[0]['id']}",
                           json={"approve": True}).status_code == 200
        t.join(2)
        assert out[0].success
        assert fake_popen.calls
        assert client.post(f"/api/approvals/{pending[0]['id']}",
                           json={"approve": True}).status_code == 404

    def test_out_of_scope_never_reaches_the_queue(self, fake_popen):
        q = ApprovalQueue(timeout=2)
        runner = ToolRunner(allowed_tools=["curl"], on_approve=q.request,
                            scope_policy=ScopePolicy(in_scope=["api.example.com"]))
        res = runner.execute("curl https://evil.org/")
        assert "OUT OF SCOPE" in res.stderr
        assert q.history() == [] and fake_popen.calls == []


def test_gui_agents_use_the_queue():
    src = (TEMPLATE.parents[1] / "app.py").read_text()
    constructions = src.count("AgentMode(")
    assert constructions >= 1
    assert src.count('on_approve=_state["approvals"].request') == constructions


class TestTemplate:
    html = TEMPLATE.read_text(encoding="utf-8")

    def test_approval_modal_and_polling(self):
        assert 'id="approvalOverlay"' in self.html
        assert "setInterval(pollApprovals, 2000)" in self.html
        assert "async function decideApproval(approve)" in self.html
        # command and reason are rendered as text, never as HTML
        assert "getElementById('approvalCommand').textContent" in self.html
        assert "getElementById('approvalReason').textContent" in self.html

    def test_findings_are_escaped(self):
        body = self.html[self.html.index("async function loadFindings()"):]
        body = body[:body.index("// ── Scripts")]
        for raw in ("${f.title}", "${f.description}", "${f.recommendation}", "${data.target}"):
            assert raw not in body, raw
        assert "escapeHtml(f.raw_title || f.title)" in body

    def test_review_actions_present(self):
        for action in ("valid", "false_positive", "needs_more_evidence", "attest", "replay"):
            assert re.search(rf"findingAction\(\$\{{i\}}, '{action}'\)", self.html), action


def test_attest_and_replay_endpoints(tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    from hackbot.gui import app as gui

    agent = MagicMock()
    agent.findings = [MagicMock()]
    agent.attest_evidence.return_value.to_dict.return_value = {"verification": "confirmed"}
    agent.reproduce_finding.return_value = {"reproduced": True}
    agent.findings[0].to_dict.return_value = {"verification": "confirmed"}
    gui._state["agent"] = agent
    client = gui.app.test_client()

    assert client.post("/api/agent/findings/0/attest", json={}).status_code == 400
    ok = client.post("/api/agent/findings/0/attest", json={"path": "/x/burp.txt", "note": "n"})
    assert ok.status_code == 200
    agent.attest_evidence.assert_called_once_with(0, "/x/burp.txt", "n")

    agent.attest_evidence.side_effect = OSError("missing")
    assert client.post("/api/agent/findings/0/attest", json={"path": "/nope"}).status_code == 400

    rep = client.post("/api/agent/findings/0/replay", json={})
    assert rep.get_json()["result"] == {"reproduced": True}
    assert client.post("/api/agent/findings/5/replay", json={}).status_code == 404
