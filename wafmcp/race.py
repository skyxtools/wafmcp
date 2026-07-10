"""Race condition oracle - detect state-corruption under concurrency.

Many "check-then-act" flows are safe sequentially but broken concurrently: a
coupon meant to be used once, a balance withdrawal, a one-per-account signup.
If N requests hit the window between the check and the act, the app may grant
more than it should.

Oracle: fire N requests that are RELEASED SIMULTANEOUSLY (threading.Barrier so
they cross the check-then-act window together), then count how many "succeeded".
Confirmed when successes exceed the operator-asserted expected_max (e.g. a
single-use coupon that applies twice). The operator supplies what success looks
like and the legitimate ceiling - the tool doesn't guess intent.

Throttle is intentionally bypassed here (via Probe.send_unthrottled): a rate
limit would serialize the burst and hide the bug. Scope and forbidden
method/path rules are still enforced. Keep N modest; this is a targeted probe,
not a flood.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .http_client import Probe, Response


@dataclass
class RaceVerdict:
    confirmed: bool
    successes: int
    expected_max: int
    concurrency: int
    confidence: float
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "oracle": "race",
            "successes": self.successes,
            "expected_max": self.expected_max,
            "concurrency": self.concurrency,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
        }


def _is_success(r: Response, success_status: int, success_marker: str | None) -> bool:
    if r.error:
        return False
    if r.status != success_status:
        return False
    if success_marker:
        return success_marker.lower() in (r.body_text or r.body_snippet or "").lower()
    return True


def verify_race(
    probe: Probe,
    *,
    method: str,
    url: str,
    concurrency: int,
    expected_max: int,
    success_status: int = 200,
    success_marker: str | None = None,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    data: Any = None,
) -> RaceVerdict:
    """Fire `concurrency` identical requests released simultaneously and count
    successes. Confirmed when successes > expected_max.

    success_status / success_marker define what "the action was granted" means.
    expected_max is the legitimate ceiling (e.g. 1 for a single-use coupon).
    """
    concurrency = max(2, min(concurrency, 50))  # sane bounds; targeted, not a flood
    barrier = threading.Barrier(concurrency)
    results: list[Response] = [None] * concurrency  # type: ignore
    errors: list[str] = []

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=15)  # all threads block here, then release together
        except threading.BrokenBarrierError:
            errors.append(f"worker {i}: barrier broken")
            return
        try:
            results[i] = probe.send_unthrottled(
                method, url, params=params, headers=headers, data=data
            )
        except Exception as e:  # OutOfScope / RuleViolation surface here
            errors.append(f"worker {i}: {type(e).__name__}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    got = [r for r in results if r is not None]
    successes = sum(1 for r in got if _is_success(r, success_status, success_marker))
    status_hist: dict[int, int] = {}
    for r in got:
        status_hist[r.status] = status_hist.get(r.status, 0) + 1

    ev = [
        f"fired {concurrency} concurrent (barrier-synced) requests",
        f"status histogram: {dict(sorted(status_hist.items()))}",
        f"successes={successes} expected_max={expected_max}",
    ]
    if errors:
        ev.append(f"errors: {errors[:3]}")
        # a scope/rule error means the burst never really ran
        if any("OutOfScope" in e or "RuleViolation" in e for e in errors):
            return RaceVerdict(False, successes, expected_max, concurrency, 0.0,
                               ev + ["burst blocked by scope/rules - not executed"])

    confirmed = successes > expected_max
    if confirmed:
        ev.append(
            f"{successes} concurrent successes exceed the legitimate ceiling of "
            f"{expected_max} -> race condition (check-then-act not atomic)"
        )
    conf = 0.9 if confirmed else 0.15
    return RaceVerdict(confirmed, successes, expected_max, concurrency, conf, ev)
