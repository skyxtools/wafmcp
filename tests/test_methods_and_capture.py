"""Live tests for HTTP method audit + login_capture."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wafmcp.http_client import Probe
from wafmcp.identities import IdentityStore
from wafmcp.methods import audit_methods
from wafmcp.scope import Scope


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


# ---- method audit ----------------------------------------------------------

def test_method_audit_flags_dangerous_accepted():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):    self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def do_POST(self):   self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        # DANGEROUSLY accepted: PUT and DELETE both return 200
        def do_PUT(self):    self.send_response(200); self.end_headers(); self.wfile.write(b"replaced")
        def do_DELETE(self): self.send_response(200); self.end_headers(); self.wfile.write(b"deleted")
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
            self.end_headers()
    srv, p, port = _serve(H)
    res = audit_methods(p, f"http://127.0.0.1:{port}/api/1")
    methods_ok = [a["method"] for a in res.accepted]
    assert "PUT" in methods_ok and "DELETE" in methods_ok
    assert "GET, POST, PUT, DELETE" in res.allow_header
    p.close(); srv.shutdown()


def test_method_audit_rejects_when_locked_down():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):  self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        # everything else returns 405
        def do_POST(self):    self.send_response(405); self.end_headers()
        def do_PUT(self):     self.send_response(405); self.end_headers()
        def do_DELETE(self):  self.send_response(405); self.end_headers()
        def do_PATCH(self):   self.send_response(405); self.end_headers()
        def do_TRACE(self):   self.send_response(405); self.end_headers()
        def do_OPTIONS(self):
            self.send_response(200); self.send_header("Allow", "GET, OPTIONS"); self.end_headers()
    srv, p, port = _serve(H)
    res = audit_methods(p, f"http://127.0.0.1:{port}/api/1")
    rejected = [r["method"] for r in res.rejected]
    for m in ("PUT", "DELETE", "PATCH", "TRACE"):
        assert m in rejected
    p.close(); srv.shutdown()


# ---- login_capture / IdentityStore cookie merge ----------------------------

def test_capture_cookies_merges_into_identity():
    store = IdentityStore()
    ident = store.capture_cookies("alice", {"session": "abc", "csrf": "xyz"})
    assert "session=abc" in ident.headers["Cookie"]
    assert "csrf=xyz" in ident.headers["Cookie"]
    # second capture merges without dropping prior cookies
    store.capture_cookies("alice", {"preferences": "dark"})
    cookie = store.get("alice").headers["Cookie"]
    assert "session=abc" in cookie
    assert "preferences=dark" in cookie
