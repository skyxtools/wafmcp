"""Offline tests for passive audit (headers, cookies, secret regex)."""
from wafmcp.http_client import Response
from wafmcp.passive import audit


def _resp(headers, body=""):
    return Response(
        url="https://t/", method="GET", status=200, length=len(body),
        elapsed_ms=1.0, body_sha1="x", headers=headers, body_snippet=body,
    )


def test_missing_security_headers():
    rep = audit(_resp({}))
    joined = " ".join(rep.missing_headers)
    assert "HSTS" in joined and "CSP" in joined


def test_present_headers_not_flagged():
    rep = audit(_resp({
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
    }))
    # only X-Frame-Options concern, satisfied by frame-ancestors -> none missing
    assert not rep.missing_headers


def test_cookie_flag_issues():
    rep = audit(_resp({"Set-Cookie": "sid=abc123; Path=/"}))
    assert rep.cookie_issues
    assert "HttpOnly" in rep.cookie_issues[0]
    assert "Secure" in rep.cookie_issues[0]


def test_secret_leak_detected_and_masked():
    body = 'const key="AKIAIOSFODNN7EXAMPLE"; token=eyJhbGciOiJ"'
    rep = audit(_resp({}, body=body))
    assert any("AWS access key" in s for s in rep.leaked_secrets)
    # masked, not raw
    assert "AKIAIOSFODNN7EXAMPLE" not in " ".join(rep.leaked_secrets)


def test_clean_response_no_secret_findings():
    rep = audit(_resp({"Strict-Transport-Security": "x"}, body="just normal html here"))
    assert not rep.leaked_secrets
