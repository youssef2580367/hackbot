"""Tests for ownership-aware BOLA/IDOR substitution and ID predictability."""

import json
import re
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlsplit

import pytest

from hackbot.config import AgentConfig, AIConfig, HackBotConfig, ScopeConfig
from hackbot.core.bola import BolaTester, classify_ids, mutate
from hackbot.core.corpus import Corpus
from hackbot.core.engine import AIEngine
from hackbot.core.identities import IdentityVault
from hackbot.core.scope import ScopePolicy

A_SESSION = "sess-" + "a" * 24
B_SESSION = "sess-" + "b" * 24
C_SESSION = "sess-" + "d" * 24

ORDERS = {"5001": "hunter-a@example.com", "5002": "hunter-b@example.com",
          "5003": "hunter-c@example.com"}
OWNER_BY_SESSION = {A_SESSION: "hunter-a@example.com", B_SESSION: "hunter-b@example.com",
                    C_SESSION: "hunter-c@example.com"}


@pytest.fixture
def vault():
    return IdentityVault.from_dict({"identities": {
        "user-a": {"cookies": {"session": A_SESSION}, "markers": ["hunter-a@example.com"],
                   "owned": {"order": ["5001"]}},
        "user-b": {"cookies": {"session": B_SESSION}, "markers": ["hunter-b@example.com"],
                   "owned": {"order": ["5002"]}},
    }})


# ── predictability ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("values,kind,ac", [
    (["5001", "5002", "5017"], "sequential integer", "L"),
    (["7"], "integer", "L"),
    (["3f2504e0-4f89-41d3-9a0c-0305e82c3301", "9a2504e0-4f89-4bd3-9a0c-0305e82c3301"],
     "random UUIDv4", "H"),
    (["3f2504e0-4f89-11d3-9a0c-0305e82c3301"], "time-based UUIDv1", "L"),
    (["66f2a1b0c3d4e5f60718293a"], "MongoDB ObjectId", "L"),
    (["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], "opaque hex", "H"),
    (["a@b.io"], "email address", "L"),
    (["tok_8xA9zQ2mN4pL7vR1sT6w"], "opaque token", "H"),
])
def test_classify_ids(values, kind, ac):
    p = classify_ids(values)
    assert p.kind.startswith(kind) and p.attack_complexity == ac


def test_sparse_integers_not_called_sequential():
    assert classify_ids(["12", "9000000"]).kind == "integer"


# ── mutation ─────────────────────────────────────────────────────────────────


def _corpus(vault):
    return Corpus(scope_policy=ScopePolicy(in_scope=["api.example.com"]), identity_vault=vault)


def _param(ex, location, name=None):
    return next(p for p in ex.params if p.location == location and (name is None or p.name == name))


class TestMutate:
    def test_path(self, vault):
        ex = _corpus(vault).add("t", "GET", "https://api.example.com/v1/orders/5001/items",
                                {"Cookie": f"session={A_SESSION}"})
        out = mutate(ex, _param(ex, "path"), "5002", "replace")
        assert out.url == "https://api.example.com/v1/orders/5002/items"
        assert ex.url.endswith("/5001/items")  # original untouched
        assert mutate(ex, _param(ex, "path"), "5002", "pollution_last") is None

    @pytest.mark.parametrize("mode,expected", [
        ("replace", [("order_id", "5002"), ("x", "1")]),
        ("pollution_last", [("order_id", "5001"), ("x", "1"), ("order_id", "5002")]),
        ("pollution_first", [("order_id", "5002"), ("order_id", "5001"), ("x", "1")]),
    ])
    def test_query(self, vault, mode, expected):
        ex = _corpus(vault).add("t", "GET", "https://api.example.com/o?order_id=5001&x=1")
        out = mutate(ex, _param(ex, "query", "order_id"), "5002", mode)
        assert parse_qsl(urlsplit(out.url).query) == expected

    def test_form_body(self, vault):
        ex = _corpus(vault).add("t", "POST", "https://api.example.com/o", {}, "order_id=5001")
        out = mutate(ex, _param(ex, "body", "order_id"), "5002", "pollution_last")
        assert out.request_body == "order_id=5001&order_id=5002"

    @pytest.mark.parametrize("mode,expected", [
        ("replace", 5002), ("type_juggle", "5002"), ("array_wrap", [5002]),
    ])
    def test_json(self, vault, mode, expected):
        ex = _corpus(vault).add("t", "POST", "https://api.example.com/o",
                                {"Content-Type": "application/json"},
                                '{"order": {"id": 5001}, "note": "x"}')
        out = mutate(ex, _param(ex, "json", "order.id"), "5002", mode)
        assert json.loads(out.request_body)["order"]["id"] == expected
        assert json.loads(ex.request_body)["order"]["id"] == 5001

    def test_json_list_path(self, vault):
        ex = _corpus(vault).add("t", "POST", "https://api.example.com/o", {},
                                '{"items": [{"order_id": "5001"}]}')
        out = mutate(ex, _param(ex, "json", "items[].order_id"), "5002", "type_juggle")
        assert json.loads(out.request_body)["items"][0]["order_id"] == 5002


# ── planning ─────────────────────────────────────────────────────────────────


def _tester(vault, corpus=None, execute=None):
    return BolaTester(corpus or _corpus(vault), vault, execute or (lambda c, e: (1, "")))


class TestPlan:
    def test_only_ledger_owned_ids_and_ledger_victims(self, vault):
        t = _tester(vault)
        t.corpus.add("t", "GET", "https://api.example.com/v1/orders/5001?ref_id=777",
                     {"Cookie": f"session={A_SESSION}"})
        report = t.plan()
        assert {c.victim_value for c in report.cases} == {"5002"}
        assert {(c.attacker, c.victim, c.location) for c in report.cases} == \
            {("user-a", "user-b", "path")}
        assert any("ref_id=777: not an object user-a owns" in s for s in report.skipped)

    def test_unattributed_sender_skipped(self, vault):
        t = _tester(vault)
        t.corpus.add("t", "GET", "https://api.example.com/v1/orders/5001")
        report = t.plan()
        assert report.cases == [] and "not a vault identity" in report.skipped[0]

    def test_case_limit(self, vault):
        t = _tester(vault)
        t.corpus.add("t", "GET", "https://api.example.com/o?order_id=5001",
                     {"Cookie": f"session={A_SESSION}"})
        assert len(t.plan(max_cases=2).cases) == 2


# ── end to end ───────────────────────────────────────────────────────────────


def _session(argv):
    return next((s for s in OWNER_BY_SESSION if s in argv), None)


def respond(owner_email, status=200):
    return (f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n"
            + json.dumps({"order_owner": owner_email}))


def server_pollution_bug(argv):
    """Authorizes on the FIRST order_id but loads the LAST one."""
    url = re.search(r"https://\S+", argv).group(0).strip("'")
    ids = [v for k, v in parse_qsl(urlsplit(url).query) if k == "order_id"]
    caller = OWNER_BY_SESSION.get(_session(argv))
    if not ids or ORDERS.get(ids[0]) != caller:
        return respond("", 403)
    return respond(ORDERS[ids[-1]])


def server_type_juggle_bug(argv):
    """Checks ownership only when the JSON id is an integer."""
    body = json.loads(re.search(r"--data-raw (\{.*\})", argv.replace("'", "")).group(1))
    oid = body["order_id"]
    caller = OWNER_BY_SESSION.get(_session(argv))
    if isinstance(oid, int) and ORDERS.get(str(oid)) != caller:
        return respond("", 403)
    return respond(ORDERS.get(str(oid), ""))


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


class TestEndToEnd:
    def test_parameter_pollution_bola(self, agent, monkeypatch):
        _serve(monkeypatch, server_pollution_bug)
        agent.corpus.add("har", "GET", "https://api.example.com/v1/order?order_id=5001",
                         {"Cookie": f"session={A_SESSION}"})
        out = agent.bola_scan()
        verdicts = {c["mode"]: c["attack"]["verdict"] for c in out["cases"]}
        assert verdicts == {"replace": "denied", "pollution_last": "exposed",
                            "pollution_first": "denied"}
        assert len(agent.findings) == 1
        f = agent.findings[0]
        assert f.confirmed, f.proof
        assert "pollution_last" in f.title
        assert "sequential integer" in f.description and "AC:L" in f.description
        assert f.validation["verdict"] == "ready_for_validator", f.validation

    def test_json_type_juggling_bola(self, agent, monkeypatch):
        _serve(monkeypatch, server_type_juggle_bug)
        approvals = []
        agent.runner.on_approve = lambda cmd, why: approvals.append(why) or True  # the human
        agent.corpus.add("har", "POST", "https://api.example.com/v1/order/lookup",
                         {"Cookie": f"session={A_SESSION}", "Content-Type": "application/json"},
                         '{"order_id": 5001}')
        out = agent.bola_scan()
        assert approvals and all("state_change" in a for a in approvals)
        verdicts = {c["mode"]: c["attack"]["verdict"] for c in out["cases"]}
        assert verdicts["type_juggle"] == "exposed"
        assert verdicts["replace"] == "denied"
        assert agent.findings[0].confirmed
        assert "was not verified" in agent.findings[0].impact  # no state-change overclaim

    def test_secure_server_no_findings(self, agent, monkeypatch):
        _serve(monkeypatch, lambda argv: respond(OWNER_BY_SESSION[_session(argv)])
               if "5002" not in argv or _session(argv) == B_SESSION else respond("", 403))
        agent.corpus.add("har", "GET", "https://api.example.com/v1/orders/5001",
                         {"Cookie": f"session={A_SESSION}"})
        out = agent.bola_scan()
        assert [c["attack"]["verdict"] for c in out["cases"]] == ["denied"]
        assert agent.findings == []

    def test_no_marker_baseline_stops_before_attack(self, agent, monkeypatch):
        calls = _serve(monkeypatch, lambda argv: respond("someone"))
        agent.corpus.add("har", "GET", "https://api.example.com/v1/orders/5001",
                         {"Cookie": f"session={A_SESSION}"})
        out = agent.bola_scan()
        assert out["cases"][0]["baseline"]["verdict"] == "no_marker"
        assert out["cases"][0]["attack"] is None
        assert len(calls) == 1  # only the victim baseline was sent

    def test_state_changing_case_waits_for_human(self, agent, monkeypatch):
        calls = _serve(monkeypatch, server_type_juggle_bug)
        agent.corpus.add("har", "DELETE", "https://api.example.com/v1/orders/5001",
                         {"Cookie": f"session={A_SESSION}"})
        out = agent.bola_scan()  # no on_approve wired → refused by the escalation gate
        assert out["cases"][0]["baseline"]["verdict"] == "blocked"
        assert out["cases"][0]["attack"] is None
        assert calls == []

    def test_plan_only_sends_nothing(self, agent, monkeypatch):
        calls = _serve(monkeypatch, server_pollution_bug)
        agent.corpus.add("har", "GET", "https://api.example.com/v1/order?order_id=5001",
                         {"Cookie": f"session={A_SESSION}"})
        out = agent.bola_scan(plan_only=True)
        assert len(out["cases"]) == 3 and calls == []

    def test_action_summary(self, agent, monkeypatch):
        _serve(monkeypatch, server_pollution_bug)
        agent.corpus.add("har", "GET", "https://api.example.com/v1/order?order_id=5001",
                         {"Cookie": f"session={A_SESSION}"})
        text = agent._process_bola_action({})
        assert "[pollution_last] → exposed" in text and "AC:L" in text


def test_requires_identities():
    from hackbot.modes.agent import AgentMode

    config = HackBotConfig()
    config.ai = AIConfig(provider="mock", model="mock")
    with patch("hackbot.core.vulndb.VulnDB"), patch("hackbot.core.cve.CVELookup"):
        a = AgentMode(engine=MagicMock(spec=AIEngine), config=config)
    assert "identities" in a.bola_scan()["refused"]
