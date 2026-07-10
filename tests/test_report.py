"""Offline tests for the PoC report generator."""
from wafmcp.report import build_report


def test_report_refuses_unconfirmed():
    out = build_report(
        title="x", severity="high", url="https://t/a",
        verdict={"confirmed": False, "oracle": "differential"},
    )
    assert out.startswith("REFUSED")


def test_report_confirmed_has_curl_and_evidence():
    verdict = {
        "confirmed": True, "oracle": "access_control", "confidence": 0.95,
        "trials": 2, "evidence": ["attacker received owner's exact resource"],
    }
    out = build_report(
        title="IDOR on /api/doc", severity="high",
        url="https://t/api/doc", method="GET", param="id", value="1",
        headers={"Authorization": "Bearer ATTACKER"},
        verdict=verdict, impact="Any user can read any document.",
    )
    assert "# IDOR on /api/doc" in out
    assert "**Severity:** High" in out
    assert "curl" in out and "id=1" in out
    assert "Bearer ATTACKER" in out
    assert "attacker received owner" in out
    assert "Any user can read any document." in out


def test_report_invalid_severity_defaults_info():
    out = build_report(
        title="x", severity="bogus", url="https://t/a",
        verdict={"confirmed": True, "oracle": "cors", "evidence": []},
    )
    assert "**Severity:** Info" in out


def test_report_does_not_duplicate_existing_query_param():
    out = build_report(
        title="x", severity="high", url="https://t/api?id=1",
        param="id", value="1",
        verdict={"confirmed": True, "oracle": "access_control", "evidence": []},
    )
    assert "id=1&id=1" not in out
    assert "id=1" in out


def test_report_appends_new_param():
    out = build_report(
        title="x", severity="high", url="https://t/api?a=2",
        param="id", value="9",
        verdict={"confirmed": True, "oracle": "access_control", "evidence": []},
    )
    assert "a=2&id=9" in out
