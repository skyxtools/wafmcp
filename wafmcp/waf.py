"""WAF calibration - establish the baseline that makes findings *real*.

Without a baseline you cannot tell three very different situations apart:
  - the WAF blocked your payload  (not a finding)
  - the app errored generically   (maybe a finding, needs verification)
  - the payload actually landed    (candidate finding)

`calibrate()` sends benign and known-hostile probes, learns the "normal" and
"blocked" response profiles, fingerprints the WAF, and returns a Baseline the
other tools consult via `classify()`.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .http_client import Probe, Response

# Deliberately loud payloads that any competent WAF blocks. Used only to learn
# the *block signature* of this specific target - never sent as real attacks.
_HOSTILE_PROBES = [
    ("query", "q", "<script>alert(1)</script>"),
    ("query", "q", "' OR '1'='1"),
    ("query", "q", "../../../../etc/passwd"),
    ("query", "q", "();+cat+/etc/passwd"),
    ("query", "q", "UNION SELECT NULL,NULL,NULL--"),
]
_BENIGN_PROBES = [
    ("query", "q", "hello"),
    ("query", "q", "product-1234"),
    ("query", "q", "search term"),
]

# Interference sources other than a blocking WAF. These don't block, but they
# can DISTORT a live test: a CDN/cache can serve a stale body that hides a real
# change, and a rate-limiter can turn a valid request into a 429 mid-test.
_CDN_HEADERS = [
    ("Cloudflare", "cf-cache-status"),
    ("Cloudflare", "cf-ray"),
    ("Fastly", "x-served-by"),
    ("Fastly", "x-cache"),
    ("Akamai", "x-akamai-transformed"),
    ("Amazon CloudFront", "x-amz-cf-id"),
    ("Amazon CloudFront", "via"),          # often "... cloudfront"
    ("Varnish", "x-varnish"),
    ("generic cache", "age"),
    ("generic cache", "x-cache"),
]
_RATELIMIT_HEADERS = [
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "ratelimit-limit",
    "ratelimit-remaining",
]


@dataclass
class Profile:
    statuses: list[int] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    body_hashes: list[str] = field(default_factory=list)

    def add(self, r: Response) -> None:
        self.statuses.append(r.status)
        self.lengths.append(r.length)
        self.body_hashes.append(r.body_sha1)

    @property
    def median_len(self) -> float:
        return statistics.median(self.lengths) if self.lengths else 0.0

    @property
    def common_statuses(self) -> set[int]:
        return set(self.statuses)


@dataclass
class Baseline:
    target: str
    waf_vendors: list[str] = field(default_factory=list)
    benign: Profile = field(default_factory=Profile)
    blocked: Profile = field(default_factory=Profile)
    block_statuses: set[int] = field(default_factory=set)
    block_hashes: set[str] = field(default_factory=set)
    # interference layers (may distort a live test even without blocking)
    cdn_vendors: list[str] = field(default_factory=list)
    cache_active: bool = False
    rate_limited: bool = False
    stable: bool = True            # identical requests gave identical responses
    stability_note: str = ""

    @property
    def waf_present(self) -> bool:
        return bool(self.waf_vendors) or bool(self.block_statuses)

    @property
    def clean(self) -> bool:
        """True when nothing in front of the app should distort a live test."""
        return not (
            self.waf_present or self.cdn_vendors or self.cache_active
            or self.rate_limited or not self.stable
        )

    def classify(self, r: Response) -> str:
        """Return one of: 'blocked', 'normal', 'anomaly'.

        - blocked: matches the learned WAF block signature
        - normal:  looks like a benign response
        - anomaly: neither - this is what merits verification (candidate)
        """
        if r.error:
            return "anomaly"
        if r.status in self.block_statuses and self.block_statuses:
            return "blocked"
        if r.body_sha1 in self.block_hashes:
            return "blocked"
        if r.blocked_heuristic and r.status in (403, 406, 429, 503):
            return "blocked"
        # close to benign length band and benign status -> normal
        if r.status in self.benign.common_statuses:
            med = self.benign.median_len
            if med and abs(r.length - med) <= max(64, 0.15 * med):
                return "normal"
        return "anomaly"

    def summary(self) -> dict[str, Any]:
        interference = self._interference_list()
        return {
            "target": self.target,
            "test_reliable": self.clean,
            "interference": interference,
            "waf_present": self.waf_present,
            "waf_vendors": self.waf_vendors,
            "cdn_vendors": self.cdn_vendors,
            "cache_active": self.cache_active,
            "rate_limited": self.rate_limited,
            "response_stable": self.stable,
            "stability_note": self.stability_note,
            "block_statuses": sorted(self.block_statuses),
            "benign_status": sorted(self.benign.common_statuses),
            "benign_median_len": round(self.benign.median_len, 1),
            "verdict": self._verdict(interference),
        }

    def _interference_list(self) -> list[str]:
        items: list[str] = []
        if self.waf_present:
            items.append(f"WAF ({', '.join(self.waf_vendors) or 'unfingerprinted'})")
        if self.cdn_vendors:
            items.append(f"CDN ({', '.join(self.cdn_vendors)})")
        if self.cache_active:
            items.append("caching layer (Age/X-Cache present)")
        if self.rate_limited:
            items.append("rate limiting (Retry-After/RateLimit headers)")
        if not self.stable:
            items.append(f"unstable responses ({self.stability_note})")
        return items

    def _verdict(self, interference: list[str]) -> str:
        if self.clean:
            return (
                "CLEAN. No WAF/CDN/cache/rate-limit detected and identical requests "
                "returned identical responses. Live testing here reflects the backend "
                "directly - differential/timing findings are trustworthy."
            )
        parts = [
            "INTERFERENCE DETECTED - a layer in front of the app may distort live "
            "test results: " + "; ".join(interference) + "."
        ]
        if self.waf_present:
            parts.append(
                "A WAF can turn a real vuln into a 'blocked' response; treat only "
                "'anomaly' classifications as candidates and confirm via verify_finding."
            )
        if self.cache_active or self.cdn_vendors:
            parts.append(
                "A cache/CDN can serve a stale body that hides a real change; add a "
                "cache-buster (unique param per request) and prefer OAST/timing oracles "
                "over pure length-differential."
            )
        if self.rate_limited:
            parts.append(
                "Rate limiting is active; lower max_rps in set_scope so a 429 mid-test "
                "isn't mistaken for a block or a fix."
            )
        if not self.stable:
            parts.append(
                "Responses to identical requests differ, so length-differential is "
                "unreliable here; rely on OAST or timing oracles instead."
            )
        return " ".join(parts)


def _scan_interference(bl: Baseline, r: Response) -> None:
    """Inspect one response's headers for CDN / cache / rate-limit signals."""
    lowered = {k.lower(): v.lower() for k, v in r.headers.items()}
    for vendor, hdr in _CDN_HEADERS:
        if hdr in lowered:
            # 'via'/'age' are generic; only count when value looks like a CDN/cache
            if hdr == "via" and "cloudfront" not in lowered[hdr]:
                continue
            if hdr == "age" and not lowered[hdr].strip().isdigit():
                continue
            if vendor not in bl.cdn_vendors and "cache" not in vendor:
                bl.cdn_vendors.append(vendor)
            if hdr in ("age", "x-cache", "cf-cache-status"):
                bl.cache_active = True
    if any(h in lowered for h in _RATELIMIT_HEADERS) or r.status == 429:
        bl.rate_limited = True


def calibrate(probe: Probe, base_url: str) -> Baseline:
    """Learn the target's normal + blocked profile AND whether any layer in front
    of the app would distort a live test (WAF/CDN/cache/rate-limit/instability)."""
    bl = Baseline(target=base_url)
    vendors: list[str] = []

    for _loc, param, val in _BENIGN_PROBES:
        r = probe.send("GET", base_url, params={param: val})
        bl.benign.add(r)
        _scan_interference(bl, r)
        for v in r.waf_hints:
            if v not in vendors:
                vendors.append(v)

    for _loc, param, val in _HOSTILE_PROBES:
        r = probe.send("GET", base_url, params={param: val})
        bl.blocked.add(r)
        _scan_interference(bl, r)
        for v in r.waf_hints:
            if v not in vendors:
                vendors.append(v)
        # A hostile probe that is NOT in the benign band is a block indicator.
        if r.status not in bl.benign.common_statuses or r.blocked_heuristic:
            bl.block_statuses.add(r.status)
            bl.block_hashes.add(r.body_sha1)

    # Stability check: same benign request several times. If the body hash or
    # length drifts, length-differential findings can't be trusted here.
    stable_val = "stability-probe-42"
    hashes: set[str] = set()
    lengths: list[int] = []
    for _ in range(4):
        r = probe.send("GET", base_url, params={"q": stable_val})
        hashes.add(r.body_sha1)
        lengths.append(r.length)
        _scan_interference(bl, r)
    if len(hashes) > 1:
        spread = max(lengths) - min(lengths)
        bl.stable = False
        bl.stability_note = f"{len(hashes)} distinct bodies, length spread {spread}B"

    bl.waf_vendors = vendors
    # Guard: don't let a benign status leak into block signature
    bl.block_statuses -= bl.benign.common_statuses
    return bl
