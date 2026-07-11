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
    body_text: str = ""             # larger slice for oracle matching (up to 200 KB)
    blocked_heuristic: bool = False
    waf_hints: list[str] = field(default_factory=list)
    error: str | None = None
    redirects: list[str] = field(default_factory=list)   # chain of Location hops followed
    cookies: dict[str, str] = field(default_factory=dict)  # parsed Set-Cookie name->value

    # Response headers most relevant to web testing, surfaced explicitly.
    _NOTABLE = (
        "location", "set-cookie", "content-type", "content-security-policy",
        "access-control-allow-origin", "access-control-allow-credentials",
        "www-authenticate", "x-powered-by", "server", "content-length",
    )

    def notable_headers(self) -> dict[str, str]:
        low = {k.lower(): v for k, v in self.headers.items()}
        return {k: low[k] for k in self._NOTABLE if k in low}

    def brief(self, full_body: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "status": self.status,
            "length": self.length,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "body_sha1": self.body_sha1[:12],
            "blocked_heuristic": self.blocked_heuristic,
            "waf_hints": self.waf_hints,
            "headers": self.notable_headers(),
            "all_headers": dict(self.headers),
            "error": self.error,
        }
        if self.redirects:
            out["redirects"] = self.redirects
            out["location"] = self.headers.get("location") or self.headers.get("Location")
        if full_body:
            out["body"] = self.body_text
        else:
            out["body_snippet"] = self.body_snippet
        return out


class HeaderError(ValueError):
    """A header key/value could not be safely encoded for transmission."""


def sanitize_headers(headers: dict | None) -> dict[str, str]:
    """Coerce header values to safe strings at the single egress point.

    Handles the common real-world cases that otherwise crash httpx:
      - non-string values from JSON (int/bool/float) -> str
      - None values                                  -> dropped
      - CR/LF in a value (header/CRLF injection)      -> rejected
      - non-latin-1 characters httpx cannot encode    -> rejected with a clear msg
    """
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if v is None:
            continue
        key = str(k)
        if isinstance(v, bool):
            val = "true" if v else "false"
        elif isinstance(v, (int, float)):
            val = str(v)
        else:
            val = str(v)
        if "\n" in key or "\r" in key or "\n" in val or "\r" in val:
            raise HeaderError(f"header {key!r} contains CR/LF (injection blocked)")
        try:
            key.encode("latin-1")
            val.encode("latin-1")
        except UnicodeEncodeError:
            raise HeaderError(
                f"header {key!r} has a non-latin-1 value; URL-encode it or use raw bytes"
            )
        out[key] = val
    return out


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
        content: str | bytes | None = None,
        follow_redirects: bool = False,
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

        return self._dispatch(
            method, url, params, headers, data, json, content, follow_redirects, extra_ua
        )

    def send_unthrottled(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        content: str | bytes | None = None,
        follow_redirects: bool = False,
        extra_ua: str | None = None,
    ) -> Response:
        """Like send() but WITHOUT throttle/jitter. Used only for race-condition
        bursts where inserting delay would defeat the test. Scope and forbidden
        method/path rules are still enforced; only the rate limit is skipped."""
        self.scope.check(url)
        self.rules.enforce(method, url)
        return self._dispatch(
            method, url, params, headers, data, json, content, follow_redirects, extra_ua
        )

    def _dispatch(
        self, method: str, url: str,
        params: dict[str, str] | None, headers: dict[str, str] | None,
        data: Any, json: Any, content: str | bytes | None,
        follow_redirects: bool, extra_ua: str | None,
    ) -> Response:
        h = dict(headers or {})
        h = self.rules.inject_headers(h)  # mandated identification headers
        if self.rotate_ua and "User-Agent" not in h and "user-agent" not in {k.lower() for k in h}:
            h["User-Agent"] = extra_ua or random.choice(_UA_POOL)
        # coerce/validate header values at the single egress point so a stray
        # int/bool/None or CRLF never crashes the request mid-tool
        try:
            h = sanitize_headers(h)
        except HeaderError as exc:
            return Response(
                url=url, method=method.upper(), status=0, length=0,
                elapsed_ms=0.0, body_sha1="", headers={}, body_snippet="",
                error=f"header error: {exc}",
            )

        # Manually walk the redirect chain so the scope gate applies to EVERY hop
        # (httpx auto-follow would bypass it). Cap hops to avoid loops.
        redirects: list[str] = []
        cur_url = url
        cur_method = method.upper()
        cur_content = content
        cur_data = data
        cur_json = json
        t0 = time.perf_counter()
        for _hop in range(10 if follow_redirects else 1):
            try:
                r = self._client.request(
                    cur_method, cur_url, params=params, headers=h,
                    data=cur_data, json=cur_json, content=cur_content,
                )
            except httpx.HTTPError as exc:
                return Response(
                    url=cur_url, method=cur_method, status=0, length=0,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                    body_sha1="", headers={}, body_snippet="", error=str(exc),
                    redirects=redirects,
                )
            except Exception as exc:  # last-resort: never let one request kill a tool
                return Response(
                    url=cur_url, method=cur_method, status=0, length=0,
                    elapsed_ms=(time.perf_counter() - t0) * 1000,
                    body_sha1="", headers={}, body_snippet="",
                    error=f"{type(exc).__name__}: {exc}", redirects=redirects,
                )
            if follow_redirects and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location")
                if not loc:
                    break
                nxt = str(httpx.URL(r.url).join(loc))
                try:
                    self.scope.check(nxt)  # every redirect target must be in scope
                except Exception:
                    # out-of-scope redirect target: stop, report where it pointed
                    redirects.append(nxt + " [OUT OF SCOPE - not followed]")
                    break
                redirects.append(nxt)
                # 303 and 302/301-on-POST degrade to GET without body
                if r.status_code == 303 or (r.status_code in (301, 302) and cur_method == "POST"):
                    cur_method = "GET"
                    cur_content = cur_data = cur_json = None
                cur_url = nxt
                params = None  # already baked into the resolved location
                continue
            break

        elapsed = (time.perf_counter() - t0) * 1000
        body = r.content or b""
        waf_hints = self._detect_waf(r)
        blocked = r.status_code in (403, 406, 429, 501, 503) or bool(waf_hints)
        return Response(
            url=str(r.url),
            method=cur_method,
            status=r.status_code,
            length=len(body),
            elapsed_ms=elapsed,
            body_sha1=hashlib.sha1(body).hexdigest(),
            headers={k: v for k, v in r.headers.items()},
            body_snippet=r.text[:512],
            body_text=r.text[:200_000],
            blocked_heuristic=blocked,
            waf_hints=waf_hints,
            redirects=redirects,
            cookies={k: v for k, v in r.cookies.items()},
        )
