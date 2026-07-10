"""Live end-to-end smoke test against a local mock target.

Proves the real flow without hitting any external host:
  - a mock server simulates boolean-based SQLi (true vs false payload diverge)
  - waf_calibrate learns baseline
  - verify_finding(differential) CONFIRMS the injectable param
  - and REJECTS a non-injectable param (no false positive)
  - scope gate blocks an out-of-scope host
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from wafmcp.scope import Scope, OutOfScope
from wafmcp.rules import Rules, RuleViolation
from wafmcp.http_client import Probe
from wafmcp.waf import calibrate
from wafmcp.verify import verify_differential


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        q = qs.get("q", [""])[0]
        safe = qs.get("safe", [""])[0]
        # Injectable param `q`: logically-true payload returns 3 rows, false returns 0.
        if "1=1" in q:
            body = b"row1 row2 row3 " * 20
        elif "1=2" in q:
            body = b"no results"
        # simulate a WAF-ish block on an obvious loud probe
        elif "<script>" in q or "/etc/passwd" in q or "UNION SELECT" in q:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"blocked by policy")
            return
        else:
            body = b"default page content here " * 10
        # non-injectable param `safe` ignores the value entirely (stable response)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def run():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}/search"
    scope = Scope(rules=[], deny=[])
    scope.configure(f"127.0.0.1:{port}", out_of_scope="")
    rules = Rules(max_rps=50.0, required_headers={"X-Bug-Bounty": "smoke-test"},
                  forbidden_paths=["/danger"], forbidden_methods=["DELETE"])
    p = Probe(scope, rules=rules)

    print("== calibrate ==")
    bl = calibrate(p, base)
    print("  waf_present:", bl.waf_present, "block_statuses:", sorted(bl.block_statuses))

    print("== verify injectable param q (should CONFIRM) ==")
    v_true = verify_differential(
        p, bl, method="GET", url=base, param="q",
        true_payload="1 AND 1=1", false_payload="1 AND 1=2", trials=3,
    )
    print(" ", v_true.to_dict())
    assert v_true.confirmed, "injectable param must be confirmed"

    print("== verify non-injectable param safe (should REJECT) ==")
    v_false = verify_differential(
        p, bl, method="GET", url=base, param="safe",
        true_payload="1 AND 1=1", false_payload="1 AND 1=2", trials=3,
    )
    print(" ", v_false.to_dict())
    assert not v_false.confirmed, "non-injectable param must NOT be confirmed (no false positive)"

    print("== scope gate blocks out-of-scope host ==")
    try:
        p.send("GET", "https://not-in-scope.example.org/")
        raise SystemExit("FAIL: out-of-scope request was allowed")
    except OutOfScope:
        print("  correctly blocked out-of-scope request")

    print("== program rules block forbidden method/path ==")
    try:
        p.send("DELETE", base)
        raise SystemExit("FAIL: forbidden method was allowed")
    except RuleViolation:
        print("  correctly blocked forbidden DELETE")
    try:
        p.send("GET", f"http://127.0.0.1:{port}/danger")
        raise SystemExit("FAIL: forbidden path was allowed")
    except RuleViolation:
        print("  correctly blocked forbidden /danger path")

    p.close()
    srv.shutdown()
    print("\nALL LIVE CHECKS PASSED")


if __name__ == "__main__":
    run()
