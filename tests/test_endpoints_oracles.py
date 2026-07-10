"""Offline tests for endpoint parsing + live tests for open-redirect and LFI."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wafmcp.endpoints import extract_endpoints, verify_lfi, verify_open_redirect
from wafmcp.http_client import Probe
from wafmcp.scope import Scope


# ---- extract_endpoints (parse only) ----------------------------------------

def test_extract_links_forms_and_js_paths():
    body = """
    <html>
      <a href="/dashboard">home</a>
      <a href="https://other.example/x">ext</a>
      <form action="/login" method="post">
        <input name="user"/><input name="pw"/>
      </form>
      <script>const API="/api/users?id=1"; fetch("/api/orders");</script>
      <img src="/static/logo.png"/>
    </html>
    """
    eps = extract_endpoints("http://target.test/", body)
    urls = {e.url for e in eps}
    assert "http://target.test/dashboard" in urls
    assert "http://target.test/login" in urls
    assert "http://target.test/api/users?id=1" in urls
    assert "http://target.test/api/orders" in urls
    # external filtered out by default
    assert not any("other.example" in u for u in urls)
    # .png filtered
    assert not any(u.endswith("logo.png") for u in urls)
    # form params captured
    login = next(e for e in eps if e.url.endswith("/login") and e.kind == "form")
    assert set(login.params) == {"user", "pw"}
    assert login.method == "POST"


def test_extract_external_included_when_requested():
    body = '<a href="https://other.example/x">x</a>'
    eps = extract_endpoints("http://target.test/", body, include_external=True)
    assert any("other.example" in e.url for e in eps)


# ---- helpers ---------------------------------------------------------------

def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


# ---- verify_open_redirect --------------------------------------------------

def test_open_redirect_confirmed():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            # naive redirect: echo whatever ?next= says
            path = self.path
            if "next=" in path:
                target = path.split("next=", 1)[1].split("&", 1)[0]
                import urllib.parse
                target = urllib.parse.unquote(target)
                self.send_response(302); self.send_header("Location", target); self.end_headers()
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    srv, p, port = _serve(H)
    v = verify_open_redirect(p, method="GET", url=f"http://127.0.0.1:{port}/go", param="next")
    assert v.confirmed, v.evidence
    assert v.location and "evil.example" in v.location
    p.close(); srv.shutdown()


def test_open_redirect_rejected_when_safe():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            # safe redirect: always to a fixed internal path
            self.send_response(302); self.send_header("Location", "/home"); self.end_headers()
    srv, p, port = _serve(H)
    v = verify_open_redirect(p, method="GET", url=f"http://127.0.0.1:{port}/go", param="next")
    assert not v.confirmed
    p.close(); srv.shutdown()


# ---- verify_lfi ------------------------------------------------------------

def test_lfi_confirmed_on_passwd_leak():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if "file=" in self.path:
                self.send_response(200); self.end_headers()
                # unconditionally leak — simulates a vulnerable file-include
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"choose a file")
    srv, p, port = _serve(H)
    v = verify_lfi(p, method="GET", url=f"http://127.0.0.1:{port}/read", param="file", target_os="unix")
    assert v.confirmed, v.evidence
    assert v.signature_matched and "passwd" in v.signature_matched.lower()
    p.close(); srv.shutdown()


def test_lfi_rejected_on_safe_reader():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(400); self.end_headers(); self.wfile.write(b"invalid file")
    srv, p, port = _serve(H)
    v = verify_lfi(p, method="GET", url=f"http://127.0.0.1:{port}/read", param="file", target_os="unix")
    assert not v.confirmed
    p.close(); srv.shutdown()
