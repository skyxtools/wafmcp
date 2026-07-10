"""Tests for program rules enforcement."""
import time

import pytest

from wafmcp.rules import Rules, RuleViolation


def test_forbidden_method():
    r = Rules(forbidden_methods=["DELETE", "PUT"])
    with pytest.raises(RuleViolation):
        r.enforce("DELETE", "https://t/x")
    r.enforce("GET", "https://t/x")  # allowed, no raise


def test_forbidden_path():
    r = Rules(forbidden_paths=["/logout", "/admin"])
    with pytest.raises(RuleViolation):
        r.enforce("GET", "https://t/admin/panel")
    r.enforce("GET", "https://t/search?q=1")


def test_required_headers_injected_without_overriding_caller():
    r = Rules(required_headers={"X-Bug-Bounty": "handle", "User-Agent": "prog"})
    out = r.inject_headers({"User-Agent": "caller-set"})
    assert out["X-Bug-Bounty"] == "handle"       # mandated header added
    assert out["User-Agent"] == "caller-set"     # caller's explicit value kept


def test_rate_limit_throttles():
    r = Rules(max_rps=5.0)  # min 200ms gap
    t0 = time.monotonic()
    r.throttle()
    r.throttle()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.18, f"throttle should enforce ~200ms gap, got {elapsed:.3f}s"
