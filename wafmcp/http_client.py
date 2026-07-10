"""WAF-aware HTTP client - the single egress point for all requests.

Everything an LLM tool wants to send goes through `Probe.send()`, which:
  1. enforces scope (default-deny),
  2. applies transport-level evasion (header rotation, jitter),
  3. records a normalized Response (status, length, timing, body hash, block signal).

Block detection is heuristic here; authoritative block classification comes
from `waf.py` which owns the calibrated baseline.
"""
from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .rules import Rules
from .scope import Scope

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# Common WAF fingerprints: (vendor, needle in header value or body).
_WAF_SIGNS = [
    ("Cloudflare", "cloudflare"),
    ("Cloudflare", "cf-ray"),
    ("Akamai", "akamai"),
    ("AWS WAF", "awselb"),
    ("Imperva/Incapsula", "incap_ses"),
    ("Imperva/Incapsula", "_incapsula_"),
    ("F5 BIG-IP ASM", "bigipserver"),
    ("Sucuri", "sucuri"),
    ("ModSecurity", "mod_security"),
    ("ModSecurity", "not acceptable"),
    ("Wordfence", "wordfence"),
    ("Barracuda", "barra_counter"),
    ("FortiWeb", "fortiwafsid"),
]


@dataclass
class Response:
    url: str
    method: str
    status: int
    length: int
    elapsed_ms: float
    body_sha1: str
    headers: dict[str, str]
    body_snippet: str               # 512 char for LLM display
    body_text: str = ""             # larger slice for oracle matching (8 KB)
    blocked_heuristic: bool = False
    waf_hints: list[str] = field(default_factory=list)
    error: str | None = None

    def brief(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "length": self.length,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "body_sha1": self.body_sha1[:12],
            "blocked_heuristic": self.blocked_heuristic,
            "waf_hints": self.waf_hints,
            "error": self.error,
        }


class Probe:
    def __init__(
        self,
        scope: Scope,
        *,
        rules: Rules | None = None,
        timeout: float = 15.0,
        jitter: tuple[float, float] = (0.0, 0.0),
        rotate_ua: bool = True,
        proxy: str | None = None,
        verify_tls: bool = False,
    ):
        self.scope = scope
        self.rules = rules or Rules()
        self.jitter = jitter
        self.rotate_ua = rotate_ua
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=verify_tls,
            proxy=proxy,
            headers={"Accept": "*/*", "Connection": "close"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Probe":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _detect_waf(self, resp: httpx.Response) -> list[str]:
        hay = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        hay += " " + resp.text[:2048].lower()
        hints: list[str] = []
        for vendor, needle in _WAF_SIGNS:
            if needle in hay and vendor not in hints:
                hints.append(vendor)
        return hints

    def send(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        extra_ua: str | None = None,
    ) -> Response:
        # 1. scope gate - hard fail if out of allowlist / matches out-of-scope
        self.scope.check(url)
        # 2. program rules - forbidden method/path (raises RuleViolation)
        self.rules.enforce(method, url)
        # 3. rate limit mandated by the program
        self.rules.throttle()

        # 4. jitter
        lo, hi = self.jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))

        return self._dispatch(method, url, params, headers, data, json, extra_ua)

    def send_unthrottled(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        extra_ua: str | None = None,
    ) -> Response:
        """Like send() but WITHOUT throttle/jitter. Used only for race-condition
        bursts where inserting delay would defeat the test. Scope and forbidden
        method/path rules are still enforced; only the rate limit is skipped."""
        self.scope.check(url)
        self.rules.enforce(method, url)
        return self._dispatch(method, url, params, headers, data, json, extra_ua)

    def _dispatch(
        self, method: str, url: str,
        params: dict[str, str] | None, headers: dict[str, str] | None,
        data: Any, json: Any, extra_ua: str | None,
    ) -> Response:
        h = dict(headers or {})
        h = self.rules.inject_headers(h)  # mandated identification headers
        if self.rotate_ua and "User-Agent" not in h and "user-agent" not in {k.lower() for k in h}:
            h["User-Agent"] = extra_ua or random.choice(_UA_POOL)

        t0 = time.perf_counter()
        try:
            r = self._client.request(
                method.upper(), url, params=params, headers=h, data=data, json=json
            )
        except httpx.HTTPError as exc:
            return Response(
                url=url, method=method.upper(), status=0, length=0,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                body_sha1="", headers={}, body_snippet="", error=str(exc),
            )
        elapsed = (time.perf_counter() - t0) * 1000
        body = r.content or b""
        waf_hints = self._detect_waf(r)
        blocked = r.status_code in (403, 406, 429, 501, 503) or bool(waf_hints)
        return Response(
            url=str(r.url),
            method=method.upper(),
            status=r.status_code,
            length=len(body),
            elapsed_ms=elapsed,
            body_sha1=hashlib.sha1(body).hexdigest(),
            headers={k: v for k, v in r.headers.items()},
            body_snippet=r.text[:512],
            body_text=r.text[:8192],
            blocked_heuristic=blocked,
            waf_hints=waf_hints,
        )
