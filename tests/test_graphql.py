"""Live mock-server tests for safe GraphQL discovery and access-control oracles."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from wafmcp.graphql_audit import audit_graphql, verify_graphql_access
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


def _send_json(handler: BaseHTTPRequestHandler, value, status: int = 200):
    body = json.dumps(value).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _post_body(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode()
    content_type = handler.headers.get("Content-Type", "").split(";", 1)[0]
    if content_type == "application/json":
        return json.loads(raw)
    if content_type == "application/x-www-form-urlencoded":
        return {"query": parse_qs(raw).get("query", [""])[0]}
    return None


def _query_response(query: str):
    if "WafmcpSchema" in query:
        return {
            "data": {
                "__schema": {
                    "queryType": {
                        "name": "Query",
                        "fields": [
                            {"name": "user", "args": [{"name": "id"}]},
                            {"name": "userEmail", "args": []},
                        ],
                    },
                    "mutationType": {
                        "name": "Mutation",
                        "fields": [{"name": "resetPassword", "args": [{"name": "id"}]}],
                    },
                    "subscriptionType": None,
                    "types": [
                        {"kind": "OBJECT", "name": "Query"},
                        {"kind": "OBJECT", "name": "Mutation"},
                        {"kind": "OBJECT", "name": "User"},
                        {"kind": "OBJECT", "name": "__Schema"},
                    ],
                }
            }
        }
    if "__schema" in query:
        return {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                }
            }
        }
    if "__typenam" in query and "__typename" not in query:
        return {"errors": [{"message": "Cannot query '__typenam'. Did you mean '__typename'?"}]}
    if "a:__typename" in query and "b:__typename" in query:
        return {"data": {"a": "Query", "b": "Query"}}
    if "__typename" in query:
        return {"data": {"__typename": "Query"}}
    return {"errors": [{"message": "Bad query"}]}


def test_graphql_audit_maps_portswigger_surfaces_without_claiming_vulnerability():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_GET(self):
            query = parse_qs(urlparse(self.path).query).get("query", [""])[0]
            _send_json(self, _query_response(query))

        def do_POST(self):
            body = _post_body(self)
            if isinstance(body, list):
                _send_json(self, [_query_response(item.get("query", "")) for item in body])
                return
            _send_json(self, _query_response((body or {}).get("query", "")))

    server, probe, port = _serve(Handler)
    result = audit_graphql(
        probe,
        url=f"http://127.0.0.1:{port}/graphql",
        include_schema=True,
    ).to_dict()
    assert result["endpoint_confirmed"]
    assert len(result["confirmed_transports"]) == 3
    signal_types = {item["type"] for item in result["signals"]}
    assert {
        "introspection_enabled",
        "graphql_suggestions_enabled",
        "csrf_transport_precondition",
        "csrf_mutation_surface",
        "aliases_accepted",
        "batching_accepted",
        "sensitive_field_names",
    }.issubset(signal_types)
    assert result["schema"]["mutation"]["fields"] == ["resetPassword"]
    assert result["confirmed_vulnerabilities"] == []
    probe.close(); server.shutdown()


def test_locked_down_graphql_endpoint_only_confirms_post_json():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_GET(self):
            _send_json(self, {"errors": [{"message": "Method not allowed"}]}, 405)

        def do_POST(self):
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                _post_body(self)
                _send_json(self, {"errors": [{"message": "JSON required"}]}, 415)
                return
            body = _post_body(self)
            if isinstance(body, list):
                _send_json(self, {"errors": [{"message": "Batching disabled"}]}, 400)
                return
            query = (body or {}).get("query", "")
            if query == "query{__typename}":
                _send_json(self, {"data": {"__typename": "Query"}})
            else:
                _send_json(self, {"errors": [{"message": "Request rejected"}]}, 400)

    server, probe, port = _serve(Handler)
    result = audit_graphql(probe, url=f"http://127.0.0.1:{port}/graphql").to_dict()
    assert result["endpoint_confirmed"]
    assert result["confirmed_transports"] == ["POST application/json"]
    assert result["signals"] == []
    probe.close(); server.shutdown()


def test_introspection_whitespace_filter_bypass_is_a_candidate():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_POST(self):
            body = _post_body(self)
            query = (body or {}).get("query", "")
            if query == "query{__typename}":
                _send_json(self, {"data": {"__typename": "Query"}})
            elif "__schema\n" in query:
                _send_json(self, {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None}}})
            else:
                _send_json(self, {"errors": [{"message": "Introspection disabled"}]}, 400)

    server, probe, port = _serve(Handler)
    result = audit_graphql(
        probe,
        url=f"http://127.0.0.1:{port}/graphql",
        test_get=False,
        test_form=False,
        test_batching=False,
        test_aliases=False,
        test_suggestions=False,
    ).to_dict()
    bypass = next(item for item in result["signals"]
                  if item["type"] == "introspection_filter_bypass")
    assert bypass["status"] == "candidate"
    probe.close(); server.shutdown()


def test_waf_shaped_response_does_not_confirm_graphql_endpoint():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            _send_json(self, {"data": {"__typename": "Query"}}, 403)
        def do_POST(self):
            _post_body(self)
            _send_json(self, {"data": {"__typename": "Query"}}, 403)

    server, probe, port = _serve(Handler)
    result = audit_graphql(probe, url=f"http://127.0.0.1:{port}/graphql").to_dict()
    assert not result["endpoint_confirmed"]
    assert result["confirmed_transports"] == []
    probe.close(); server.shutdown()


def test_graphql_access_confirmed_when_attacker_reads_owner_data():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            _post_body(self)
            if not self.headers.get("Authorization"):
                _send_json(self, {"data": None, "errors": [{"message": "Login required"}]}, 401)
                return
            _send_json(self, {"data": {"user": {"id": "1", "email": "alice@example.test"}}})

    server, probe, port = _serve(Handler)
    verdict = verify_graphql_access(
        probe,
        url=f"http://127.0.0.1:{port}/graphql",
        query="query User($id: ID!){user(id:$id){id email}}",
        variables={"id": "1"},
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert verdict.confirmed, verdict.to_dict()
    probe.close(); server.shutdown()


def test_graphql_access_rejects_public_data():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            _post_body(self)
            _send_json(self, {"data": {"product": {"id": "1", "name": "Public"}}})

    server, probe, port = _serve(Handler)
    verdict = verify_graphql_access(
        probe,
        url=f"http://127.0.0.1:{port}/graphql",
        query="query{product(id:1){id name}}",
        variables={},
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert not verdict.confirmed
    assert any("public" in item for item in verdict.evidence)
    probe.close(); server.shutdown()


def test_graphql_access_rejects_properly_scoped_data():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            _post_body(self)
            auth = self.headers.get("Authorization", "")
            if not auth:
                _send_json(self, {"data": None, "errors": [{"message": "Login required"}]}, 401)
                return
            _send_json(self, {"data": {"profile": {"owner": auth}}})

    server, probe, port = _serve(Handler)
    verdict = verify_graphql_access(
        probe,
        url=f"http://127.0.0.1:{port}/graphql",
        query="query{profile{id}}",
        variables={},
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert not verdict.confirmed
    probe.close(); server.shutdown()


def test_graphql_access_refuses_mutations_before_sending():
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        def log_message(self, *args): pass
        def do_POST(self):
            Handler.requests += 1
            _post_body(self)
            _send_json(self, {"data": {"deleteUser": True}})

    server, probe, port = _serve(Handler)
    with pytest.raises(ValueError, match="read-only"):
        verify_graphql_access(
            probe,
            url=f"http://127.0.0.1:{port}/graphql",
            query="mutation{deleteUser(id:1)}",
            variables={},
            owner_headers={"Authorization": "Bearer ALICE"},
            attacker_headers={"Authorization": "Bearer BOB"},
        )
    assert Handler.requests == 0
    probe.close(); server.shutdown()
