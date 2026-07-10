"""Offline tests for the pure logic: scope gate, mutation, baseline classify.

These don't touch the network — they verify the guardrail and the oracle math,
which are the parts that make findings trustworthy.
"""
from wafmcp.scope import Scope, OutOfScope
from wafmcp.mutate import mutate
from wafmcp.waf import Baseline, Profile
from wafmcp.http_client import Response


def _resp(status, length, sha="a" * 40, blocked=False, waf=None):
    return Response(
        url="https://t/", method="GET", status=status, length=length,
        elapsed_ms=10.0, body_sha1=sha, headers={}, body_snippet="",
        blocked_heuristic=blocked, waf_hints=waf or [],
    )


# ---- scope -----------------------------------------------------------------

def test_scope_default_deny():
    s = Scope.load("")  # empty
    try:
        s.check("https://example.com/")
        assert False, "empty scope must deny"
    except OutOfScope:
        pass


def test_scope_exact_and_wildcard():
    s = Scope.load("api.example.com,*.corp.internal")
    assert s.check("https://api.example.com/x") == ("api.example.com", 443)
    assert s.check("http://a.corp.internal/") == ("a.corp.internal", 80)
    # apex should NOT match wildcard
    try:
        s.check("https://corp.internal/")
        assert False
    except OutOfScope:
        pass
    # unrelated host denied
    try:
        s.check("https://evil.com/")
        assert False
    except OutOfScope:
        pass


def test_deny_wins_over_allow():
    # in-scope wildcard, but a specific host carved out as out-of-scope
    s = Scope.load("*.target.com", "admin.target.com")
    assert s.check("https://app.target.com/")[0] == "app.target.com"
    try:
        s.check("https://admin.target.com/")
        assert False, "out-of-scope must win over in-scope"
    except OutOfScope:
        pass


def test_configure_runtime():
    s = Scope(rules=[], deny=[])
    assert not s.configured
    s.configure("api.test.com", "no.test.com")
    assert s.configured
    assert s.check("https://api.test.com/")[0] == "api.test.com"


def test_scope_cidr_and_port():
    s = Scope.load("10.0.0.0/24,host.test:8443")
    assert s.check("http://10.0.0.5:80/")[0] == "10.0.0.5"
    try:
        s.check("http://10.0.1.5/")
        assert False
    except OutOfScope:
        pass
    # port-restricted rule
    assert s.check("https://host.test:8443/")[1] == 8443
    try:
        s.check("https://host.test:443/")
        assert False
    except OutOfScope:
        pass


# ---- mutate ----------------------------------------------------------------

def test_mutate_produces_distinct_ordered_variants():
    vs = mutate("' OR '1'='1", context="url", limit=10)
    payloads = [v.payload for v in vs]
    assert len(payloads) == len(set(payloads)), "variants must be de-duplicated"
    assert vs[0].technique == "raw", "raw/stealthiest first"
    # url_encode variant must actually differ from raw
    enc = [v for v in vs if v.technique == "url_encode"]
    assert enc and enc[0].payload != "' OR '1'='1"


def test_mutate_technique_filter():
    vs = mutate("a b", techniques=["tab_whitespace"], limit=5)
    assert all(v.technique == "tab_whitespace" for v in vs)
    assert vs[0].payload == "a\tb"


# ---- baseline classify -----------------------------------------------------

def _baseline():
    bl = Baseline(target="https://t/")
    for _ in range(3):
        bl.benign.add(_resp(200, 1000))
    bl.block_statuses = {403}
    bl.block_hashes = {"b" * 40}
    return bl


def test_classify_blocked_by_status():
    bl = _baseline()
    assert bl.classify(_resp(403, 50, blocked=True)) == "blocked"


def test_classify_normal_in_band():
    bl = _baseline()
    assert bl.classify(_resp(200, 1010)) == "normal"


def test_classify_anomaly_is_candidate():
    bl = _baseline()
    # 200 but wildly different length => not blocked, not normal => candidate
    assert bl.classify(_resp(200, 50000)) == "anomaly"
    # 500 error, unseen => anomaly (worth verifying), not a silent pass
    assert bl.classify(_resp(500, 300)) == "anomaly"
