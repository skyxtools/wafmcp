"""Tests for interference detection — the reliability verdict for live testing.

The point of calibration in a bug-bounty context is to confirm the target is
CLEAN (no WAF/CDN/cache/rate-limit) so live test results reflect the backend and
aren't distorted. These tests drive calibrate() against mock servers.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from wafmcp.scope import Scope
from wafmcp.http_client import Probe
from wafmcp.waf import calibrate


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[])
    scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), f"http://127.0.0.1:{port}/"


def test_clean_target_is_reliable():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"stable body always the same")
    srv, p, url = _serve(H)
    bl = calibrate(p, url)
    assert bl.clean, bl.summary()
    assert bl.summary()["test_reliable"] is True
    assert not bl.cdn_vendors and not bl.cache_active and not bl.rate_limited and bl.stable
    p.close(); srv.shutdown()


def test_cdn_and_cache_detected():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("CF-RAY", "abc123-SIN")
            self.send_header("CF-Cache-Status", "HIT")
            self.send_header("Age", "42")
            self.end_headers()
            self.wfile.write(b"cached body")
    srv, p, url = _serve(H)
    bl = calibrate(p, url)
    assert not bl.clean
    assert bl.cache_active
    assert "Cloudflare" in bl.cdn_vendors
    assert "cache" in bl.summary()["verdict"].lower()
    p.close(); srv.shutdown()


def test_rate_limit_detected():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("X-RateLimit-Remaining", "3")
            self.end_headers()
            self.wfile.write(b"ok")
    srv, p, url = _serve(H)
    bl = calibrate(p, url)
    assert bl.rate_limited
    assert not bl.clean
    p.close(); srv.shutdown()


def test_unstable_responses_flagged():
    counter = {"n": 0}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            counter["n"] += 1
            self.send_response(200)
            self.end_headers()
            # body changes every request -> length-differential unreliable
            self.wfile.write(b"x" * (10 + counter["n"] * 7))
    srv, p, url = _serve(H)
    bl = calibrate(p, url)
    assert not bl.stable
    assert not bl.clean
    assert "unreliable" in bl.summary()["verdict"].lower()
    p.close(); srv.shutdown()
