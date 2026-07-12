"""Context, HTTP, DOM, payload, and browser-orchestration tests for XSS tools."""
from __future__ import annotations

import html
import importlib.util
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from wafmcp.http_client import Probe
from wafmcp.rules import Rules
from wafmcp.scope import Scope
from wafmcp.waf import Baseline
from wafmcp.xss import (
    _websocket_scope_url,
    analyze_dom_javascript,
    audit_reflected_xss,
    build_xss_payloads,
    reflection_contexts,
    verify_stored_xss_page,
    verify_xss_execution,
)

_HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


def _has_chromium_runtime() -> bool:
    if not _HAS_PLAYWRIGHT:
        return False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).exists()
    except Exception:
        return False


_HAS_CHROMIUM = _has_chromium_runtime()


def test_websocket_scope_url_preserves_explicit_ports_and_maps_default_schemes() -> None:
    assert _websocket_scope_url("wss://example.test/socket?token=x") == (
        "https://example.test/socket?token=x"
    )
    assert _websocket_scope_url("ws://example.test:8080/socket") == (
        "http://example.test:8080/socket"
    )


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.05)
    scope = Scope(); scope.configure(f"127.0.0.1:{port}")
    return server, Probe(scope), port


def test_context_parser_maps_html_attributes_urls_and_javascript_strings():
    marker = "wxcontextyz"
    body = f"""
    <div>{marker}</div>
    <input value="{marker}">
    <a href='{marker}'>link</a>
    <script>
      const a = '{marker}';
      const b = "{marker}";
      const c = `{marker}`;
      const d = {marker};
    </script>
    <!-- {marker} -->
    """
    contexts = reflection_contexts(body, marker)
    names = {item["context"] for item in contexts}
    assert {
        "html_text",
        "html_attribute",
        "url_attribute",
        "javascript_single_string",
        "javascript_double_string",
        "javascript_template_literal",
        "javascript_code",
        "html_comment",
    }.issubset(names)
    value = next(item for item in contexts if item["context"] == "html_attribute")
    assert value["quote"] == "double"
    href = next(item for item in contexts if item["context"] == "url_attribute")
    assert href["quote"] == "single"


def test_reflected_xss_raw_html_is_candidate_but_never_http_confirmed():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            value = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body><div>{value}</div></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

    server, probe, port = _serve(Handler)
    result = audit_reflected_xss(
        probe,
        Baseline(target=f"http://127.0.0.1:{port}/search"),
        method="GET",
        url=f"http://127.0.0.1:{port}/search",
        param="q",
    ).to_dict()
    assert result["reflected"]
    assert result["candidate"]
    assert not result["confirmed"]
    assert result["classification"] == "browser_execution_required"
    assert result["raw_meta_characters"]["<"]
    assert result["raw_meta_characters"][">"]
    probe.close(); server.shutdown()


def test_reflected_xss_context_encoding_is_not_candidate():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            value = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body><div>{html.escape(value, quote=True)}</div></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(body)

    server, probe, port = _serve(Handler)
    result = audit_reflected_xss(
        probe,
        Baseline(target=f"http://127.0.0.1:{port}/search"),
        method="GET",
        url=f"http://127.0.0.1:{port}/search",
        param="q",
    )
    assert result.reflected
    assert not result.candidate
    assert result.classification == "encoded_or_non_executable_reflection"
    assert not result.raw_meta_characters["<"]
    assert not result.raw_meta_characters['"']
    probe.close(); server.shutdown()


def test_json_reflection_is_not_reported_as_browser_xss_candidate():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            value = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = json.dumps({"query": value}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(body)

    server, probe, port = _serve(Handler)
    result = audit_reflected_xss(
        probe,
        Baseline(target=f"http://127.0.0.1:{port}/api"),
        method="GET",
        url=f"http://127.0.0.1:{port}/api",
        param="q",
    )
    assert result.reflected
    assert not result.candidate
    assert result.classification == "non_html_reflection"
    probe.close(); server.shutdown()


def test_non_get_reflection_probe_requires_explicit_state_change_confirmation():
    scope = Scope(); scope.configure("example.test")
    probe = Probe(scope)
    with pytest.raises(ValueError, match="confirm_state_change"):
        audit_reflected_xss(
            probe,
            Baseline(target="https://example.test/search"),
            method="POST",
            url="https://example.test/search",
            param="q",
            in_body=True,
        )
    probe.close()


def test_dom_analysis_separates_sources_sinks_and_confirmation():
    source = """
    const input = window.location.hash;
    const other = window.name;
    document.querySelector('#result').innerHTML = input;
    setTimeout(other, 10);
    """
    result = analyze_dom_javascript(source)
    assert {item["type"] for item in result["sources"]} == {"location", "window_name"}
    assert {item["type"] for item in result["sinks"]} == {"html_sink", "javascript_execution_sink"}
    assert result["candidate"]
    assert not result["confirmed"]
    assert "does not prove data flow" in result["note"]


def test_xss_payloads_are_marker_only_and_token_is_validated():
    result = build_xss_payloads("safe_token_123")
    assert len(result["payloads"]) == 14
    names = {item["name"] for item in result["payloads"]}
    assert {"double_attribute_event", "javascript_single_string_backslash"} <= names
    joined = "\n".join(item["payload"] for item in result["payloads"])
    assert "__wafmcpXssHit" in joined
    for forbidden in ("document.cookie", "localStorage", "fetch(", "XMLHttpRequest", "http://", "https://"):
        assert forbidden not in joined


def test_browser_execution_requires_stable_marker_result_from_runner():
    scope = Scope(); scope.configure("example.test")
    seen = {}

    def runner(scope_arg, **kwargs):
        seen.update(kwargs)
        payload = kwargs["payloads"][0]
        return {
            "executed": True,
            "winning_payload": payload,
            "observations": [{"payload_name": payload["name"], "stable_execution": True}],
            "blocked_out_of_scope_resources": [],
            "browser_error": None,
        }

    verdict = verify_xss_execution(
        scope,
        rules=Rules(required_headers={"X-Bug-Bounty": "tester"}),
        url="https://example.test/search",
        param="q",
        injection_location="query",
        trials=2,
        browser_runner=runner,
    )
    assert verdict.confirmed
    assert verdict.xss_type == "dom_or_reflected_xss"
    assert seen["trials"] == 2
    assert all("__wafmcpXssHit" in item["payload"] for item in seen["payloads"])


@pytest.mark.skipif(not _HAS_CHROMIUM, reason="playwright chromium runtime not installed")
def test_browser_live_confirms_safe_reflected_marker():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_GET(self):
            value = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body>{value}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    scope = Scope(); scope.configure(f"127.0.0.1:{port}")
    try:
        verdict = verify_xss_execution(
            scope,
            url=f"http://127.0.0.1:{port}/",
            param="q",
            trials=1,
            wait_ms=100,
            timeout_ms=5_000,
        )
        assert verdict.confirmed, verdict.browser
        assert verdict.browser["winning_payload"]["name"] == "html_img_onerror"
    finally:
        server.shutdown()


def test_stored_xss_oracle_only_views_existing_marker_page():
    scope = Scope(); scope.configure("example.test")

    def runner(scope_arg, **kwargs):
        assert kwargs["injection_location"] == "existing"
        assert kwargs["payloads"] == [{"name": "stored_existing_marker", "context": "stored", "payload": ""}]
        return {
            "executed": True,
            "winning_payload": kwargs["payloads"][0],
            "observations": [],
            "blocked_out_of_scope_resources": [],
            "browser_error": None,
        }

    verdict = verify_stored_xss_page(
        scope,
        url="https://example.test/comments/1",
        token="stored_token_1",
        browser_runner=runner,
    )
    assert verdict.confirmed
    assert verdict.xss_type == "stored_xss"
    assert any("only viewed" in item for item in verdict.evidence)
