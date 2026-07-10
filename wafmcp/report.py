"""Report generator - turn a CONFIRMED finding into a submittable PoC.

Triagers reject unclear reports. This produces clean markdown with a copy-paste
curl repro, the oracle evidence that proves the finding is real, and an impact
statement - the difference between a paid report and a closed-as-informative one.

It deliberately refuses to emit a report for an unconfirmed verdict: no evidence,
no report.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

_SEVERITY = {"critical", "high", "medium", "low", "info"}


def _curl(method: str, url: str, headers: dict[str, str], param: str | None,
          value: str | None, in_body: bool) -> str:
    parts = ["curl", "-i", "-sk", "-X", method.upper()]
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    target = url
    if param is not None:
        if in_body:
            parts += ["--data", f"{param}={value or ''}"]
        elif re.search(rf"[?&]{re.escape(param)}=", url):
            # param already present in the query string; don't duplicate it
            target = url
        else:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}{param}={value or ''}"
    parts.append(target)
    return " ".join(shlex.quote(p) for p in parts)


def build_report(
    *,
    title: str,
    severity: str,
    url: str,
    method: str = "GET",
    param: str | None = None,
    value: str | None = None,
    in_body: bool = False,
    headers: dict[str, str] | None = None,
    verdict: dict[str, Any] | None = None,
    impact: str = "",
    notes: str = "",
) -> str:
    sev = severity.lower().strip()
    if sev not in _SEVERITY:
        sev = "info"
    verdict = verdict or {}
    confirmed = bool(verdict.get("confirmed"))
    headers = headers or {}

    if not confirmed:
        return (
            "REFUSED: verdict is not confirmed. Only report findings an oracle has "
            "confirmed (verify_* with confirmed=true). Unverified candidate -> not a report."
        )

    ev_lines = "\n".join(f"- {e}" for e in verdict.get("evidence", [])) or "- (none)"
    repro = _curl(method, url, headers, param, value, in_body)

    return f"""# {title}

**Severity:** {sev.capitalize()}
**Endpoint:** `{method.upper()} {url}`
{f"**Parameter:** `{param}`" if param else ""}

## Summary
{notes or title}

## Steps to reproduce
```bash
{repro}
```

## Evidence (oracle: {verdict.get("oracle", "?")}, confidence {verdict.get("confidence", "?")})
{ev_lines}

## Impact
{impact or "See severity. Provide concrete impact for the affected data/users."}

---
*Verified by an {verdict.get("oracle", "?")} oracle over {verdict.get("trials", "?")} trial(s); confirmed={confirmed}.*
"""
