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

def test_cors_confirmed_only_with_cookie_identity_and_private_response():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)  # reflects attacker
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
        cookie_same_site="None",
        cookie_secure=True,
    )
    assert v.confirmed, v.to_dict()
    assert "attacker_origin" in v.details["confirmed_cases"]
    p.close(); srv.shutdown()


def test_cors_reflection_without_login_is_candidate_not_finding():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers(); self.wfile.write(b"public response")
    srv, p, port = _serve(H)
    v = verify_cors(p, url=f"http://127.0.0.1:{port}/api")
    assert not v.confirmed, v.to_dict()
    assert v.details["classification"] == "policy_candidate"
    assert "attacker_origin" in v.details["policy_candidates"]
    p.close(); srv.shutdown()


def test_cors_lax_cookie_is_not_cross_site_browser_exploitation():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
        cookie_same_site="Lax",
        cookie_secure=True,
    )
    assert not v.confirmed, v.to_dict()
    assert v.details["classification"] == "policy_candidate"
    assert not v.details["cookie_policy"]["cross_site_eligible"]
    assert any("SameSite=Lax blocks" in item for item in v.evidence)
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


def test_cors_confirmed_for_whitelisted_null_with_private_response():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin == "null":
                self.send_header("Access-Control-Allow-Origin", "null")
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
        cookie_same_site="None",
        cookie_secure=True,
    )
    assert v.confirmed, v.to_dict()
    assert "null_origin" in v.details["confirmed_cases"]
    p.close(); srv.shutdown()


def test_cors_wildcard_with_credentials_is_not_credentialed_access():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
    )
    assert not v.confirmed, v.to_dict()
    assert any("not credentialed browser access" in item for item in v.evidence)
    p.close(); srv.shutdown()


def test_cors_wildcard_confirmed_only_for_explicit_intranet_context():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers(); self.wfile.write(b"internal directory")
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        intranet_target=True,
    )
    assert v.confirmed, v.to_dict()
    assert "intranet_wildcard" in v.details["confirmed_cases"]
    p.close(); srv.shutdown()


def test_cors_detects_portswigger_prefix_parser_bypass():
    trusted = "https://normal-website.com"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin.startswith(trusted):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
        trusted_origin=trusted,
        cookie_same_site="None",
        cookie_secure=True,
    )
    assert v.confirmed, v.to_dict()
    assert "prefix_parser_bypass" in v.details["confirmed_cases"]
    prefix = next(
        item for item in v.details["observations"]
        if item["case"] == "prefix_parser_bypass"
    )
    assert prefix["origin"] == "https://normal-website.com.evil.example"
    p.close(); srv.shutdown()


def test_cors_trusted_origin_is_not_exploitable_without_separate_prerequisite():
    trusted = "https://trusted.example"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin == trusted:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = b"private account data" if self.headers.get("Cookie") else b"login required"
            self.wfile.write(body)
    srv, p, port = _serve(H)
    v = verify_cors(
        p,
        url=f"http://127.0.0.1:{port}/api",
        identity_headers={"Cookie": "session=alice"},
        trusted_origin=trusted,
    )
    assert not v.confirmed, v.to_dict()
    trusted_observation = next(
        item for item in v.details["observations"] if item["case"] == "trusted_origin"
    )
    assert not trusted_observation["attacker_generatable"]
    assert any("verify XSS" in item for item in v.evidence)
    p.close(); srv.shutdown()


# ---- reflected XSS ---------------------------------------------------------

def test_reflection_unencoded_is_candidate_until_browser_execution():
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
    assert not v.confirmed, v.to_dict()
    assert v.details["candidate"]
    assert v.details["classification"] == "browser_execution_required"
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
