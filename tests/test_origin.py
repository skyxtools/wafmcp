"""Tests for origin IP discovery — candidate filtering + oracle validation."""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from wafmcp.scope import Scope
from wafmcp.http_client import Probe, Response
from wafmcp.origin import is_cdn_ip, _title, gather_candidates, validate_origin, OriginCandidate


# ---- pure logic ------------------------------------------------------------

def test_cdn_ranges_excluded():
    assert is_cdn_ip("104.16.1.1")        # Cloudflare
    assert is_cdn_ip("151.101.1.1")       # Fastly
    assert not is_cdn_ip("203.0.113.7")   # arbitrary non-CDN
    assert not is_cdn_ip("not-an-ip")


def test_title_extraction():
    assert _title("<html><title> Hello  World </title></html>") == "Hello World"
    assert _title("<p>no title</p>") == ""


def test_gather_excludes_cdn(monkeypatch):
    import wafmcp.origin as o
    # apex resolves to a CDN IP + a real origin; CDN one must be dropped
    monkeypatch.setattr(o, "_resolve", lambda n: ["104.16.5.5", "203.0.113.9"] if n == "t.com" else [])
    monkeypatch.setattr(o, "_crtsh_subdomains", lambda h, timeout=15.0: set())
    cands = gather_candidates("t.com", use_crtsh=False)
    assert "203.0.113.9" in cands
    assert "104.16.5.5" not in cands   # CDN excluded


# ---- live validation oracle ------------------------------------------------

def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return srv, port


def _baseline(body: bytes) -> Response:
    return Response(
        url="http://t/", method="GET", status=200, length=len(body),
        elapsed_ms=1.0, body_sha1="base", headers={},
        body_snippet=body.decode(), body_text=body.decode(),
    )


def test_validate_confirms_real_origin():
    page = b"<html><title>ACME Portal</title><body>welcome</body></html>"

    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(page)
    srv, port = _serve(Origin)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    p = Probe(scope)

    # baseline = same page as the (mock) through-CDN response
    baseline = _baseline(page)
    cand = OriginCandidate(ip=f"127.0.0.1")
    # point validation at the mock's port by using host:port as the "ip"
    cand.ip = f"127.0.0.1:{port}"
    validate_origin(p, "acme.com", cand, baseline, scheme="http")
    assert cand.confirmed, cand.evidence
    p.close(); srv.shutdown()


def test_validate_rejects_decoy():
    real = b"<html><title>ACME Portal</title>welcome to acme</html>"
    decoy = b"<html><title>Unrelated Parking Page</title>buy this domain</html>"

    class Decoy(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(decoy)
    srv, port = _serve(Decoy)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    p = Probe(scope)

    baseline = _baseline(real)
    cand = OriginCandidate(ip=f"127.0.0.1:{port}")
    validate_origin(p, "acme.com", cand, baseline, scheme="http")
    assert not cand.confirmed, cand.evidence
    p.close(); srv.shutdown()
