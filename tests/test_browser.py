"""Tests for the opt-in browser module.

Framing-verdict logic is pure and always tested. The live render is exercised
only when Playwright + a browser binary are installed, and against a LOCAL mock
(never a remote target) so the suite stays hermetic.
"""
import importlib.util
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wafmcp.browser import _frame_verdict, browser_inspect, BrowserUnavailable
from wafmcp.scope import Scope

_HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


# ---- framing verdict (pure logic, always runs) -----------------------------

def test_frame_verdict_xfo_deny_protected():
    frameable, why = _frame_verdict({"X-Frame-Options": "DENY"})
    assert frameable is False and "X-Frame-Options" in why


def test_frame_verdict_csp_self_protected():
    frameable, why = _frame_verdict(
        {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"}
    )
    assert frameable is False


def test_frame_verdict_no_protection_frameable():
    frameable, why = _frame_verdict({"Content-Type": "text/html"})
    assert frameable is True and "embeddable" in why


def test_frame_verdict_permissive_csp_frameable():
    frameable, why = _frame_verdict(
        {"Content-Security-Policy": "frame-ancestors https://*.partner.com"}
    )
    assert frameable is True and "permissive" in why


# ---- graceful degradation --------------------------------------------------

@pytest.mark.skipif(_HAS_PLAYWRIGHT, reason="playwright IS installed")
def test_browser_unavailable_message():
    scope = Scope(rules=[], deny=[]); scope.configure("127.0.0.1:1")
    with pytest.raises(BrowserUnavailable) as e:
        browser_inspect(scope, "http://127.0.0.1:1/")
    assert "pip install playwright" in str(e.value)


# ---- live render against a local mock --------------------------------------

@pytest.mark.skipif(not _HAS_PLAYWRIGHT, reason="playwright not installed")
def test_browser_live_detects_iframe_and_framing():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # NO X-Frame-Options -> frameable; a JS-injected iframe appears in DOM
            self.end_headers()
            self.wfile.write(b"""<html><head><title>Mock</title></head><body>
              <script>
                const f=document.createElement('iframe');
                f.src='https://example.com/proxy'; f.name='proxyframe';
                document.body.appendChild(f);
                window.addEventListener('message', ()=>{});
              </script></body></html>""")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    rep = browser_inspect(scope, f"http://127.0.0.1:{port}/", wait_ms=1500)
    assert rep.error is None, rep.error
    assert rep.frameable is True                       # no XFO
    assert any(f["src"] and "example.com/proxy" in f["src"] for f in rep.iframes)
    assert rep.pm_listener_count >= 1                   # our addEventListener hooked
    srv.shutdown()
