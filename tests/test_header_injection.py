"""Regression tests for the header-injection bug found in real engagement.

viatorapi.viator.com failed because a non-string header value (int/bool from
JSON) crashed httpx with a TypeError that wasn't caught. These lock in the fix.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wafmcp.http_client import Probe, sanitize_headers, HeaderError
from wafmcp.scope import Scope


def test_sanitize_coerces_non_string_values():
    out = sanitize_headers({"X-Api-Version": 2, "X-Debug": True, "X-Ratio": 1.5})
    assert out == {"X-Api-Version": "2", "X-Debug": "true", "X-Ratio": "1.5"}


def test_sanitize_drops_none():
    assert sanitize_headers({"X-A": None, "X-B": "keep"}) == {"X-B": "keep"}


def test_sanitize_blocks_crlf_injection():
    with pytest.raises(HeaderError):
        sanitize_headers({"X-Evil": "value\r\nInjected: 1"})
    with pytest.raises(HeaderError):
        sanitize_headers({"X-Evil": "a\nb"})


def test_sanitize_rejects_non_latin1():
    with pytest.raises(HeaderError):
        sanitize_headers({"X-Name": "café-über-中文"})


def _serve():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            # echo back a header we received to prove it was sent as a string
            self.send_response(200)
            self.send_header("X-Seen-Version", self.headers.get("X-Api-Version", "none"))
            self.end_headers(); self.wfile.write(b"ok")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


def test_probe_survives_int_header_value():
    # THE bug: this used to raise TypeError and kill the tool mid-request.
    srv, p, port = _serve()
    r = p.send("GET", f"http://127.0.0.1:{port}/", headers={"X-Api-Version": 2})
    assert r.status == 200
    assert r.headers.get("x-seen-version") == "2"
    p.close(); srv.shutdown()


def test_probe_crlf_header_returns_clean_error_not_crash():
    srv, p, port = _serve()
    r = p.send("GET", f"http://127.0.0.1:{port}/", headers={"X-Evil": "a\r\nInjected: 1"})
    assert r.status == 0
    assert "header error" in (r.error or "")
    p.close(); srv.shutdown()
