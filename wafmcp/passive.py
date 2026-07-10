"""Passive audit - signal extracted from a response we already have.

Zero extra requests: given one response, surface low-hanging, deterministic
findings that bug-bounty programs still pay for - missing security headers,
weak cookie flags, and (highest value) secrets accidentally leaked in the body.

This is signal, not confirmed findings; the LLM should still weigh impact. But
a leaked live API key or JWT is about as real as it gets.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .http_client import Response

# High-signal secret patterns. Kept tight to avoid noise.
_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
]

# Security headers whose ABSENCE is a (usually low-sev) finding.
_EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS missing (no transport downgrade protection)",
    "content-security-policy": "CSP missing (weaker XSS mitigation)",
    "x-content-type-options": "X-Content-Type-Options missing (MIME sniffing)",
    "x-frame-options": "X-Frame-Options/CSP frame-ancestors missing (clickjacking)",
}


@dataclass
class PassiveReport:
    url: str
    missing_headers: list[str] = field(default_factory=list)
    cookie_issues: list[str] = field(default_factory=list)
    leaked_secrets: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.missing_headers or self.cookie_issues or self.leaked_secrets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "has_findings": self.has_findings,
            "missing_security_headers": self.missing_headers,
            "cookie_issues": self.cookie_issues,
            "leaked_secrets": self.leaked_secrets,
        }


def _analyze_cookies(set_cookie: str) -> list[str]:
    """Set-Cookie may contain multiple cookies joined; check flags per cookie."""
    issues: list[str] = []
    # httpx merges duplicate Set-Cookie with ", " - split conservatively on cookie name=
    for chunk in re.split(r",(?=[^;]+?=)", set_cookie):
        low = chunk.lower()
        name = chunk.split("=", 1)[0].strip()
        if not name:
            continue
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "secure" not in low:
            flags.append("Secure")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            issues.append(f"cookie {name!r} missing: {', '.join(flags)}")
    return issues


def audit(response: Response) -> PassiveReport:
    rep = PassiveReport(url=response.url)
    lowered = {k.lower(): v for k, v in response.headers.items()}

    for hdr, note in _EXPECTED_HEADERS.items():
        if hdr not in lowered:
            # X-Frame-Options can be satisfied by CSP frame-ancestors
            if hdr == "x-frame-options" and "frame-ancestors" in lowered.get(
                "content-security-policy", ""
            ):
                continue
            rep.missing_headers.append(note)

    if "set-cookie" in lowered:
        rep.cookie_issues = _analyze_cookies(lowered["set-cookie"])

    body = response.body_text or response.body_snippet
    for label, pat in _SECRET_PATTERNS:
        for m in pat.findall(body):
            snippet = m if isinstance(m, str) else m[0]
            masked = snippet[:6] + "…" + snippet[-4:] if len(snippet) > 12 else snippet
            rep.leaked_secrets.append(f"{label}: {masked}")

    return rep
