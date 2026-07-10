"""Tests for subdomain takeover detection."""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from wafmcp.scope import Scope
from wafmcp.http_client import Probe
from wafmcp.takeover import check_takeover, _match_service, TakeoverResult


# ---- service matching ------------------------------------------------------

def test_match_service_github():
    svc = _match_service(["target.github.io"])
    assert svc and svc["service"] == "GitHub Pages"


def test_match_service_s3():
    svc = _match_service(["foo.s3.amazonaws.com"])
    assert svc and svc["service"] == "AWS S3 bucket"


def test_match_service_none():
    assert _match_service(["target.internal.corp"]) is None
    assert _match_service([]) is None


# ---- live confirm / reject -------------------------------------------------

def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


def test_takeover_confirmed(monkeypatch):
    # mock a GitHub Pages unclaimed response
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(404); self.end_headers()
            self.wfile.write(b"<h1>There isn't a GitHub Pages site here.</h1>")
    srv, p, port = _serve(H)
    # force the CNAME chain to look like GitHub Pages
    import wafmcp.takeover as t
    monkeypatch.setattr(t, "resolve_cname_chain", lambda h: ["victim.github.io"])
    res = check_takeover(p, f"127.0.0.1:{port}", scheme="http")
    assert res.confirmed, res.evidence
    assert res.service == "GitHub Pages"
    assert res.confidence >= 0.9
    p.close(); srv.shutdown()


def test_takeover_rejected_when_claimed(monkeypatch):
    # CNAME to GitHub Pages but a real site is served -> not a takeover
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<h1>Welcome to our real project</h1>")
    srv, p, port = _serve(H)
    import wafmcp.takeover as t
    monkeypatch.setattr(t, "resolve_cname_chain", lambda h: ["victim.github.io"])
    res = check_takeover(p, f"127.0.0.1:{port}", scheme="http")
    assert not res.confirmed, res.evidence
    assert res.service == "GitHub Pages"  # service still identified
    p.close(); srv.shutdown()


def test_no_cname_no_finding(monkeypatch):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    srv, p, port = _serve(H)
    import wafmcp.takeover as t
    monkeypatch.setattr(t, "resolve_cname_chain", lambda h: [])
    res = check_takeover(p, f"127.0.0.1:{port}", scheme="http")
    assert not res.confirmed
    assert res.service is None
    p.close(); srv.shutdown()
