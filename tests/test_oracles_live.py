"""Live tests for the new bug-bounty oracles against mock vulnerable servers.

Each mock simulates exactly one vuln class so the oracle's confirm/reject logic
is exercised end-to-end without touching any external host.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from wafmcp.scope import Scope
from wafmcp.http_client import Probe
from wafmcp.waf import Baseline
from wafmcp.verify import verify_access_control, verify_cors, verify_reflection


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[])
    scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


# ---- IDOR / access control -------------------------------------------------

def test_idor_confirmed_when_attacker_reads_owner():
    # Vulnerable: any authenticated user can read doc 1; anon is denied.
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            auth = self.headers.get("Authorization")
            if not auth:
                self.send_response(401); self.end_headers(); self.wfile.write(b"login required"); return
            self.send_response(200); self.end_headers()
            self.wfile.write(b"SECRET DOCUMENT OWNED BY ALICE")  # same for any token = IDOR
    srv, p, port = _serve(H)
    url = f"http://127.0.0.1:{port}/api/doc?id=1"
    v = verify_access_control(
        p, method="GET", url=url,
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert v.confirmed, v.to_dict()
    p.close(); srv.shutdown()


def test_idor_rejected_when_properly_scoped():
    # Secure: response body is tied to the token -> attacker gets different body.
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if not auth:
                self.send_response(401); self.end_headers(); self.wfile.write(b"login"); return
            self.send_response(200); self.end_headers()
            self.wfile.write(f"doc for {auth}".encode())  # per-user body
    srv, p, port = _serve(H)
    url = f"http://127.0.0.1:{port}/api/doc?id=1"
    v = verify_access_control(
        p, method="GET", url=url,
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert not v.confirmed, v.to_dict()
    p.close(); srv.shutdown()


def test_idor_rejected_when_public():
    # Public resource: anon also gets it -> not an IDOR.
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"public data")
    srv, p, port = _serve(H)
    url = f"http://127.0.0.1:{port}/pub"
    v = verify_access_control(
        p, method="GET", url=url,
        owner_headers={"Authorization": "Bearer ALICE"},
        attacker_headers={"Authorization": "Bearer BOB"},
    )
    assert not v.confirmed
    assert any("PUBLIC" in e for e in v.evidence)
    p.close(); srv.shutdown()


# ---- CORS ------------------------------------------------------------------

def test_cors_confirmed_reflects_origin_with_creds():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)  # reflects attacker
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers(); self.wfile.write(b"ok")
    srv, p, port = _serve(H)
    v = verify_cors(p, url=f"http://127.0.0.1:{port}/api")
    assert v.confirmed, v.to_dict()
    p.close(); srv.shutdown()


def test_cors_rejected_when_locked_down():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "https://trusted.example")
            self.end_headers(); self.wfile.write(b"ok")
    srv, p, port = _serve(H)
    v = verify_cors(p, url=f"http://127.0.0.1:{port}/api")
    assert not v.confirmed
    p.close(); srv.shutdown()


# ---- reflected XSS ---------------------------------------------------------

def test_reflection_confirmed_unencoded():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self.send_response(200); self.end_headers()
            self.wfile.write(f"<div>results for {q}</div>".encode())  # raw reflect
    srv, p, port = _serve(H)
    v = verify_reflection(
        p, Baseline(target=f"http://127.0.0.1:{port}/"),
        method="GET", url=f"http://127.0.0.1:{port}/s", param="q",
    )
    assert v.confirmed, v.to_dict()
    p.close(); srv.shutdown()


def test_reflection_rejected_when_encoded():
    import html
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self.send_response(200); self.end_headers()
            self.wfile.write(f"<div>results for {html.escape(q)}</div>".encode())  # escaped
    srv, p, port = _serve(H)
    v = verify_reflection(
        p, Baseline(target=f"http://127.0.0.1:{port}/"),
        method="GET", url=f"http://127.0.0.1:{port}/s", param="q",
    )
    assert not v.confirmed, v.to_dict()
    p.close(); srv.shutdown()
