"""Live mock-server and offline tests for business-logic flaw oracles."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wafmcp.http_client import Probe
from wafmcp.logic_flaws import (
    build_logic_test_plan,
    verify_logic_invariant,
    verify_workflow_gate,
)
from wafmcp.scope import OutOfScope, Scope


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.05)
    scope = Scope(rules=[], deny=[])
    scope.configure(f"127.0.0.1:{port}")
    return server, Probe(scope), port


def _send(handler: BaseHTTPRequestHandler, value, status: int = 200):
    body = json.dumps(value).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0"))
    return json.loads(handler.rfile.read(length).decode())


def test_logic_plan_maps_client_trust_inputs_sequence_and_declared_invariants():
    result = build_logic_test_plan({
        "name": "checkout",
        "steps": [
            {
                "name": "cart",
                "method": "PATCH",
                "parameters": [
                    {"name": "quantity", "type": "integer", "required": True, "client_controlled": True},
                    {"name": "price", "type": "number", "client_controlled": True, "server_owned": True},
                ],
            },
            {
                "name": "purchase",
                "method": "POST",
                "prerequisites": ["cart"],
                "parameters": [{"name": "coupon", "type": "string", "required": False}],
            },
        ],
        "invariants": [
            {"path": "total", "operator": "gte", "value": 0, "description": "order total cannot be negative"}
        ],
    })
    assert result["workflow"] == "checkout"
    trust = result["test_plan"]["client_side_trust"]
    assert {item["parameter"] for item in trust} == {"quantity", "price"}
    sequence = result["test_plan"]["workflow_sequence"]
    assert any(item["test"] == "skip_prerequisite" for item in sequence)
    assert any(item["test"] == "repeat_step" for item in sequence)
    assert result["declared_invariants"][0]["assertion"] == "total gte 0"
    assert result["confirmed_vulnerabilities"] == []


def test_logic_plan_rejects_invalid_invariant_instead_of_guessing_domain_rule():
    with pytest.raises(ValueError, match="operator"):
        build_logic_test_plan({
            "steps": [{"name": "checkout", "parameters": []}],
            "invariants": [{"path": "total", "operator": "looks_bad", "value": 0}],
        })


def test_workflow_gate_confirms_fresh_session_reaches_protected_outcome():
    class Handler(BaseHTTPRequestHandler):
        methods = []
        def log_message(self, *args): pass
        def do_GET(self):
            Handler.methods.append("GET")
            cookie = self.headers.get("Cookie", "")
            if cookie in {"flow=completed", "flow=fresh"}:
                _send(self, {"access": "granted", "account": "test"})
            else:
                _send(self, {"access": "denied"}, 401)

    server, probe, port = _serve(Handler)
    verdict = verify_workflow_gate(
        probe,
        url=f"http://127.0.0.1:{port}/workflow/final",
        completed_headers={"Cookie": "flow=completed"},
        fresh_headers={"Cookie": "flow=fresh"},
        success_assertion={"path": "access", "operator": "eq", "value": "granted"},
    )
    assert verdict.confirmed, verdict.to_dict()
    assert set(Handler.methods) == {"GET"}
    probe.close(); server.shutdown()


def test_workflow_gate_rejects_properly_enforced_prerequisite():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            if cookie == "flow=completed":
                _send(self, {"access": "granted"})
            elif cookie == "flow=fresh":
                _send(self, {"access": "pending"}, 403)
            else:
                _send(self, {"access": "denied"}, 401)

    server, probe, port = _serve(Handler)
    verdict = verify_workflow_gate(
        probe,
        url=f"http://127.0.0.1:{port}/workflow/final",
        completed_headers={"Cookie": "flow=completed"},
        fresh_headers={"Cookie": "flow=fresh"},
        success_assertion={"path": "access", "operator": "eq", "value": "granted"},
    )
    assert not verdict.confirmed
    assert not verdict.candidate
    probe.close(); server.shutdown()


def test_workflow_gate_does_not_confirm_public_outcome():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, {"access": "granted"})

    server, probe, port = _serve(Handler)
    verdict = verify_workflow_gate(
        probe,
        url=f"http://127.0.0.1:{port}/public",
        completed_headers={"Cookie": "flow=completed"},
        fresh_headers={"Cookie": "flow=fresh"},
        success_assertion={"path": "access", "operator": "eq", "value": "granted"},
    )
    assert not verdict.confirmed
    assert not verdict.candidate
    assert any("public behavior" in item for item in verdict.evidence)
    probe.close(); server.shutdown()


def test_logic_invariant_confirms_persisted_violation_and_verified_restore():
    state = {"balance": 100, "status": "open"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, state)
        def do_PATCH(self):
            state.update(_read_json(self))
            _send(self, state)

    server, probe, port = _serve(Handler)
    url = f"http://127.0.0.1:{port}/account"
    verdict = verify_logic_invariant(
        probe,
        action_url=url,
        state_url=url,
        action_method="PATCH",
        action_body={"balance": -10},
        invariants=[{"path": "balance", "operator": "gte", "value": 0}],
        restore_url=url,
        restore_method="PATCH",
        restore_body={"balance": 100},
        confirm_state_change=True,
    )
    assert verdict.confirmed, verdict.to_dict()
    assert verdict.violated == ["balance gte 0"]
    assert verdict.restored
    assert state["balance"] == 100
    probe.close(); server.shutdown()


def test_logic_invariant_rejects_input_when_server_preserves_rule():
    state = {"balance": 100}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, state)
        def do_PATCH(self):
            body = _read_json(self)
            state["balance"] = max(0, body.get("balance", state["balance"]))
            _send(self, state)

    server, probe, port = _serve(Handler)
    url = f"http://127.0.0.1:{port}/account"
    verdict = verify_logic_invariant(
        probe,
        action_url=url,
        state_url=url,
        action_method="PATCH",
        action_body={"balance": -10},
        invariants=[{"path": "balance", "operator": "gte", "value": 0}],
        restore_url=url,
        restore_method="PATCH",
        restore_body={"balance": 100},
        confirm_state_change=True,
    )
    assert not verdict.confirmed
    assert verdict.violated == []
    assert verdict.restored
    probe.close(); server.shutdown()


def test_logic_invariant_requires_opt_in_and_never_allows_delete():
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        def log_message(self, *args): pass
        def do_GET(self):
            Handler.requests += 1
            _send(self, {"balance": 100})

    server, probe, port = _serve(Handler)
    kwargs = dict(
        action_url=f"http://127.0.0.1:{port}/account",
        state_url=f"http://127.0.0.1:{port}/account",
        action_method="PATCH",
        action_body={"balance": -10},
        invariants=[{"path": "balance", "operator": "gte", "value": 0}],
        restore_url=f"http://127.0.0.1:{port}/account",
        restore_method="PATCH",
        restore_body={"balance": 100},
    )
    with pytest.raises(ValueError, match="confirm_state_change"):
        verify_logic_invariant(probe, **kwargs)
    assert Handler.requests == 0
    kwargs["action_method"] = "DELETE"
    with pytest.raises(ValueError, match="DELETE"):
        verify_logic_invariant(probe, **kwargs, confirm_state_change=True)
    assert Handler.requests == 0
    probe.close(); server.shutdown()


def test_logic_invariant_preflights_restore_scope_before_any_request():
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        def log_message(self, *args): pass
        def do_GET(self):
            Handler.requests += 1
            _send(self, {"balance": 100})
        def do_PATCH(self):
            Handler.requests += 1
            _send(self, {})

    server, probe, port = _serve(Handler)
    url = f"http://127.0.0.1:{port}/account"
    with pytest.raises(OutOfScope):
        verify_logic_invariant(
            probe,
            action_url=url,
            state_url=url,
            action_method="PATCH",
            action_body={"balance": -10},
            invariants=[{"path": "balance", "operator": "gte", "value": 0}],
            restore_url="https://out-of-scope.example/restore",
            restore_method="PATCH",
            restore_body={"balance": 100},
            confirm_state_change=True,
        )
    assert Handler.requests == 0
    probe.close(); server.shutdown()


def test_logic_invariant_never_confirms_when_restore_cannot_be_verified():
    state = {"balance": 100}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, state)
        def do_PATCH(self):
            body = _read_json(self)
            if body.get("balance") != 100:
                state.update(body)
            _send(self, state)

    server, probe, port = _serve(Handler)
    url = f"http://127.0.0.1:{port}/account"
    verdict = verify_logic_invariant(
        probe,
        action_url=url,
        state_url=url,
        action_method="PATCH",
        action_body={"balance": -10},
        invariants=[{"path": "balance", "operator": "gte", "value": 0}],
        restore_url=url,
        restore_method="PATCH",
        restore_body={"balance": 100},
        confirm_state_change=True,
    )
    assert not verdict.confirmed
    assert verdict.violated
    assert not verdict.restored
    assert "URGENT" in verdict.to_dict()["next_steps"][0]
    probe.close(); server.shutdown()
