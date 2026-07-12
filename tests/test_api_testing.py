"""Live mock-server and offline tests for PortSwigger-aligned API tooling."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from wafmcp.api_testing import (
    audit_api,
    mass_assignment_candidates,
    summarize_openapi,
    verify_api_sspp,
    verify_mass_assignment,
)
from wafmcp.http_client import Probe
from wafmcp.scope import Scope


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.05)
    scope = Scope(rules=[], deny=[])
    scope.configure(f"127.0.0.1:{port}")
    return server, Probe(scope), port


def _send(handler: BaseHTTPRequestHandler, value, status: int = 200, content_type: str = "application/json"):
    body = json.dumps(value).encode() if content_type == "application/json" else str(value).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0"))
    return json.loads(handler.rfile.read(length).decode())


def test_api_audit_discovers_json_spec_and_ui_without_claiming_vulnerability():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Example API"},
        "paths": {"/users/{id}": {"get": {"operationId": "getUser"}}},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Allow", "GET, PATCH, OPTIONS")
            self.end_headers()

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/users/1":
                _send(self, {"id": 1, "email": "alice@example.test"})
            elif path == "/openapi.json":
                _send(self, spec)
            elif path == "/swagger/index.html":
                _send(self, "<html><div id='swagger-ui'></div></html>", content_type="text/html")
            else:
                _send(self, {"error": "not found"}, 404)

    server, probe, port = _serve(Handler)
    result = audit_api(probe, url=f"http://127.0.0.1:{port}/users/1").to_dict()
    assert result["endpoint"]["json_response"]
    assert {item["kind"] for item in result["documentation"]} == {
        "OpenAPI JSON", "interactive API documentation"
    }
    assert next(item for item in result["documentation"] if item["kind"] == "OpenAPI JSON")["operation_count"] == 1
    assert result["confirmed_vulnerabilities"] == []
    assert {item["status"] for item in result["signals"]} == {"attack_surface"}
    probe.close(); server.shutdown()


def test_api_audit_does_not_treat_block_page_as_documentation():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_OPTIONS(self): _send(self, {"error": "blocked"}, 403)
        def do_GET(self):
            _send(self, "<html>Swagger UI - access denied by Cloudflare</html>", 403, "text/html")

    server, probe, port = _serve(Handler)
    result = audit_api(probe, url=f"http://127.0.0.1:{port}/api").to_dict()
    assert result["documentation"] == []
    assert result["signals"] == []
    probe.close(); server.shutdown()


def test_openapi_summary_maps_operations_auth_and_sensitive_schema_fields():
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Accounts"},
        "servers": [{"url": "https://api.example.test"}],
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string"},
                        "isAdmin": {"type": "boolean"},
                        "profile": {"type": "object", "properties": {"accountId": {"type": "string"}}},
                    },
                }
            },
        },
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path", "required": True}],
                "patch": {
                    "operationId": "updateUser",
                    "requestBody": {"content": {"application/json": {}, "application/xml": {}}},
                    "security": [{"bearerAuth": []}],
                },
            }
        },
    }
    result = summarize_openapi(document)
    assert result["spec_version"] == "3.1.0"
    assert result["operation_count"] == 1
    assert result["operations"][0]["method"] == "PATCH"
    assert result["operations"][0]["request_content_types"] == ["application/json", "application/xml"]
    assert result["security_schemes"] == [{"name": "bearerAuth", "type": "http", "scheme": "bearer"}]
    assert result["review_sensitive_schema_fields"] == ["User.isAdmin", "User.profile.accountId"]
    assert result["confirmed_vulnerabilities"] == []


def test_mass_assignment_candidate_diff_is_offline_and_marks_sensitive_names():
    result = mass_assignment_candidates(
        {"id": 7, "email": "a@example.test", "profile": {"role": "user", "displayName": "A"}},
        {"email": "b@example.test", "profile": {"displayName": "B"}},
    )
    assert [item["field"] for item in result["candidates"]] == ["id", "profile.role"]
    assert [item["field"] for item in result["sensitive_candidates"]] == ["profile.role"]
    assert result["confirmed_vulnerabilities"] == []


def test_sspp_confirms_only_when_injected_duplicate_matches_direct_override():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            outer = parse_qs(urlparse(self.path).query).get("name", [""])[0]
            effective = outer
            if "&name=" in outer:
                effective = outer.rsplit("&name=", 1)[1]
            elif "#" in outer:
                effective = outer.split("#", 1)[0]
            _send(self, {"user": effective})

    server, probe, port = _serve(Handler)
    verdict = verify_api_sspp(
        probe,
        url=f"http://127.0.0.1:{port}/lookup",
        parameter="name",
        baseline_value="peter",
        override_value="carlos",
    )
    assert verdict.confirmed, verdict.to_dict()
    assert verdict.confidence == "high"
    probe.close(); server.shutdown()


def test_sspp_response_difference_without_override_oracle_is_only_candidate():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            value = parse_qs(urlparse(self.path).query).get("name", [""])[0]
            _send(self, {"echo": value})

    server, probe, port = _serve(Handler)
    verdict = verify_api_sspp(
        probe,
        url=f"http://127.0.0.1:{port}/lookup",
        parameter="name",
        baseline_value="peter",
        override_value="carlos",
    )
    assert not verdict.confirmed
    assert verdict.candidate
    probe.close(); server.shutdown()


def test_mass_assignment_changes_and_restores_observed_original_value():
    state = {"id": 1, "displayName": "Alice", "role": "user"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, state)
        def do_PATCH(self):
            state.update(_read_json(self))
            _send(self, state)

    server, probe, port = _serve(Handler)
    verdict = verify_mass_assignment(
        probe,
        update_url=f"http://127.0.0.1:{port}/users/1",
        read_url=f"http://127.0.0.1:{port}/users/1",
        method="PATCH",
        base_object={"displayName": "Alice"},
        candidate_field="role",
        test_value="auditor",
        confirm_state_change=True,
    )
    assert verdict.confirmed, verdict.to_dict()
    assert verdict.changed and verdict.restored
    assert state["role"] == "user"
    probe.close(); server.shutdown()


def test_mass_assignment_refuses_without_opt_in_before_any_request():
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        def log_message(self, *args): pass
        def do_GET(self):
            Handler.requests += 1
            _send(self, {"role": "user"})
        def do_PATCH(self):
            Handler.requests += 1
            _send(self, {})

    server, probe, port = _serve(Handler)
    with pytest.raises(ValueError, match="confirm_state_change"):
        verify_mass_assignment(
            probe,
            update_url=f"http://127.0.0.1:{port}/users/1",
            read_url=f"http://127.0.0.1:{port}/users/1",
            method="PATCH",
            base_object={},
            candidate_field="role",
            test_value="auditor",
        )
    assert Handler.requests == 0
    probe.close(); server.shutdown()


def test_mass_assignment_ignored_field_is_not_confirmed_and_delete_is_rejected():
    state = {"displayName": "Alice", "role": "user"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): _send(self, state)
        def do_PATCH(self):
            body = _read_json(self)
            if "displayName" in body:
                state["displayName"] = body["displayName"]
            _send(self, state)

    server, probe, port = _serve(Handler)
    verdict = verify_mass_assignment(
        probe,
        update_url=f"http://127.0.0.1:{port}/users/1",
        read_url=f"http://127.0.0.1:{port}/users/1",
        method="PATCH",
        base_object={"displayName": "Alice"},
        candidate_field="role",
        test_value="auditor",
        confirm_state_change=True,
    )
    assert not verdict.confirmed
    assert not verdict.changed
    assert verdict.restored
    with pytest.raises(ValueError, match="DELETE"):
        verify_mass_assignment(
            probe,
            update_url=f"http://127.0.0.1:{port}/users/1",
            read_url=f"http://127.0.0.1:{port}/users/1",
            method="DELETE",
            base_object={},
            candidate_field="role",
            test_value="auditor",
            confirm_state_change=True,
        )
    probe.close(); server.shutdown()
