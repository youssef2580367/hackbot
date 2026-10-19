"""Tests for the request corpus (import, attribution, redaction, templating)."""

import json
from types import SimpleNamespace

import pytest

from hackbot.core.corpus import Corpus, path_template, value_type
from hackbot.core.identities import IdentityVault
from hackbot.core.scope import ScopePolicy

A_SESSION = "sess-" + "a" * 24
B_TOKEN = "tok-" + "b" * 30


@pytest.fixture
def vault():
    return IdentityVault.from_dict({"identities": {
        "user-a": {"cookies": {"session": A_SESSION}, "markers": ["hunter-a@example.com"],
                   "owned": {"order": ["5001"]}},
        "user-b": {"bearer": B_TOKEN, "markers": ["hunter-b@example.com"],
                   "owned": {"order": ["5002"]}},
    }})


@pytest.fixture
def corpus(vault):
    return Corpus(scope_policy=ScopePolicy(in_scope=["*.example.com"]), identity_vault=vault)


def _har(entries):
    return {"log": {"entries": entries}}


def _entry(method, url, headers=None, body=None, status=200, resp=""):
    req = {"method": method, "url": url,
           "headers": [{"name": k, "value": v} for k, v in (headers or {}).items()]}
    if body is not None:
        req["postData"] = {"mimeType": "application/json", "text": body}
    return {"request": req, "response": {"status": status, "headers": [],
                                         "content": {"text": resp}}}


@pytest.mark.parametrize("value,typ", [
    ("5002", "int"), ("3f2504e0-4f89-11d3-9a0c-0305e82c3301", "uuid"),
    ("a3f9c2d1e4b5a6c7d8e9", "hex"), ("x@y.io", "email"), ("orders", "string"),
    (7, "int"), (True, "bool"),
])
def test_value_type(value, typ):
    assert value_type(value) == typ


def test_path_template():
    tpl, variables = path_template("/v1/users/1002/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    assert tpl == "/v1/users/{int}/orders/{uuid}"
    assert [v[2] for v in variables] == ["int", "uuid"]


class TestHarImport:
    def test_attribution_redaction_and_scope(self, corpus, tmp_path):
        har = tmp_path / "s.har"
        har.write_text(json.dumps(_har([
            _entry("GET", "https://api.example.com/v1/orders/5001",
                   {"Cookie": f"session={A_SESSION}"}, resp='{"id": 5001}'),
            _entry("GET", "https://api.example.com/v1/orders/5002",
                   {"Authorization": f"Bearer {B_TOKEN}"}, resp=f'{{"echo": "{B_TOKEN}"}}'),
            _entry("GET", "https://api.example.com/health"),
            _entry("GET", "https://cdn.other.net/x.js"),
        ])))
        assert corpus.import_har(str(har)) == 3
        assert corpus.dropped_out_of_scope == 1
        a, b, anon = corpus.exchanges
        assert (a.identity, b.identity, anon.identity) == ("user-a", "user-b", "anonymous")
        dump = json.dumps([e.to_dict() for e in corpus.exchanges])
        assert A_SESSION not in dump and B_TOKEN not in dump
        assert "<redacted:user-b.bearer>" in b.response_body

    def test_unknown_credentials_are_not_anonymous(self, corpus, tmp_path):
        har = tmp_path / "s.har"
        har.write_text(json.dumps(_har([_entry("GET", "https://api.example.com/me",
                                               {"Cookie": "session=someone-else"})])))
        corpus.import_har(str(har))
        assert corpus.exchanges[0].identity == ""

    def test_json_body_params_and_id_candidates(self, corpus, tmp_path):
        har = tmp_path / "s.har"
        har.write_text(json.dumps(_har([
            _entry("POST", "https://api.example.com/v1/transfer?account_id=5002",
                   {"Cookie": f"session={A_SESSION}", "Content-Type": "application/json"},
                   body='{"to": {"user_id": 1002}, "amount": 5, "note": "hi"}'),
        ])))
        corpus.import_har(str(har))
        ids = {(c["location"], c["param"]): c for c in corpus.id_candidates()}
        assert ("query", "account_id") in ids and ids[("query", "account_id")]["owner"] == "user-b"
        assert ("json", "to.user_id") in ids
        assert not any(c["param"] == "amount" for c in ids.values())

    def test_secret_in_query_never_reaches_params(self, corpus, tmp_path):
        har = tmp_path / "s.har"
        har.write_text(json.dumps(_har([
            _entry("GET", f"https://api.example.com/export?token={B_TOKEN}&order_id=5001")])))
        corpus.import_har(str(har))
        ex = corpus.exchanges[0]
        assert B_TOKEN not in json.dumps(ex.to_dict())
        assert ex.identity == "user-b"  # attributed by the token in the URL


def test_openapi_import(corpus, tmp_path):
    spec = tmp_path / "api.yaml"
    spec.write_text("""
openapi: 3.0.0
servers: [{url: "https://api.example.com/v2"}]
paths:
  /users/{userId}:
    get:
      parameters: [{name: userId, in: path, schema: {type: integer}}]
    delete: {}
  /admin/reports: {get: {}}
""")
    assert corpus.import_openapi(str(spec)) == 3
    eps = {(e["method"], e["template"]) for e in corpus.endpoints()}
    assert ("DELETE", "/users/{userId}") not in eps  # template is {param}
    assert ("DELETE", "/users/{param}") in eps and ("GET", "/admin/reports") in eps
    assert all(e.identity == "" for e in corpus.exchanges)


def test_openapi_out_of_scope_server(tmp_path):
    spec = tmp_path / "api.json"
    spec.write_text(json.dumps({"swagger": "2.0", "host": "evil.org", "basePath": "/api",
                                "paths": {"/x": {"get": {}}}}))
    c = Corpus(scope_policy=ScopePolicy(in_scope=["*.example.com"]))
    assert c.import_openapi(str(spec)) == 0
    assert c.dropped_out_of_scope == 1


def test_proxy_import(corpus):
    req = SimpleNamespace(url="https://api.example.com/v1/orders/5001", method="GET",
                          is_https=True, host="api.example.com", path="/v1/orders/5001",
                          request_headers={"Cookie": f"session={A_SESSION}"}, request_body="",
                          status_code=200, response_headers={}, response_body='{"id":5001}')
    engine = SimpleNamespace(get_traffic=lambda: [req])
    assert corpus.import_proxy(engine) == 1
    assert corpus.exchanges[0].identity == "user-a"


def test_endpoints_group_and_persistence(vault, tmp_path):
    store = tmp_path / "corpus.jsonl"
    c = Corpus(identity_vault=vault, path=store)
    c.add("test", "GET", "https://api.example.com/v1/orders/5001",
          {"Cookie": f"session={A_SESSION}"}, status=200)
    c.add("test", "GET", "https://api.example.com/v1/orders/5002",
          {"Authorization": f"Bearer {B_TOKEN}"}, status=200)
    eps = c.endpoints()
    assert len(eps) == 1 and eps[0]["template"] == "/v1/orders/{int}"
    assert eps[0]["identities"] == ["user-a", "user-b"]
    assert A_SESSION not in store.read_text()
    reloaded = Corpus(path=store)
    assert len(reloaded.exchanges) == 2
    assert reloaded.add("test", "GET", "https://api.example.com/x").id == 3
