"""Live tests for the race-condition oracle.

A naive check-then-act coupon (no lock) over-grants under concurrency -> must be
confirmed. A locked counter grants exactly once -> must be rejected. This proves
the oracle detects a real race and doesn't cry wolf on a safe implementation.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

from wafmcp.scope import Scope
from wafmcp.http_client import Probe
from wafmcp.race import verify_race


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    scope = Scope(rules=[], deny=[]); scope.configure(f"127.0.0.1:{port}")
    return srv, Probe(scope), port


def test_race_confirmed_on_naive_coupon():
    # VULNERABLE: check-then-act with a deliberate gap, no lock -> over-grants.
    state = {"used": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            if not state["used"]:            # check
                time.sleep(0.05)             # window between check and act
                state["used"] = True         # act
                self.send_response(200); self.end_headers(); self.wfile.write(b"COUPON APPLIED")
            else:
                self.send_response(409); self.end_headers(); self.wfile.write(b"already used")
    srv, p, port = _serve(H)
    v = verify_race(
        p, method="POST", url=f"http://127.0.0.1:{port}/redeem",
        concurrency=8, expected_max=1, success_status=200, success_marker="COUPON APPLIED",
    )
    assert v.confirmed, v.to_dict()
    assert v.successes > 1
    p.close(); srv.shutdown()


def test_race_rejected_on_locked_coupon():
    # SAFE: a lock makes check-then-act atomic -> exactly one success.
    state = {"used": False}
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            with lock:
                if not state["used"]:
                    time.sleep(0.05)
                    state["used"] = True
                    ok = True
                else:
                    ok = False
            if ok:
                self.send_response(200); self.end_headers(); self.wfile.write(b"COUPON APPLIED")
            else:
                self.send_response(409); self.end_headers(); self.wfile.write(b"already used")
    srv, p, port = _serve(H)
    v = verify_race(
        p, method="POST", url=f"http://127.0.0.1:{port}/redeem",
        concurrency=8, expected_max=1, success_status=200, success_marker="COUPON APPLIED",
    )
    assert not v.confirmed, v.to_dict()
    assert v.successes == 1
    p.close(); srv.shutdown()


def test_race_scope_gate_blocks_out_of_scope():
    scope = Scope(rules=[], deny=[]); scope.configure("127.0.0.1:1")  # nothing real
    p = Probe(scope)
    v = verify_race(
        p, method="POST", url="http://127.0.0.1:9/redeem",
        concurrency=4, expected_max=1,
    )
    assert not v.confirmed
    p.close()
