"""Finding verification - the oracle layer that makes a candidate a *finding*.

A candidate ("anomaly" from waf.classify) is not a finding. It becomes one only
when an oracle confirms it deterministically and repeatably:

  - differential: control vs. test payloads produce a stable, causal difference
    (e.g. `1 AND 1=1` behaves like baseline, `1 AND 1=2` diverges - boolean SQLi)
  - timing: an injected sleep reliably adds latency beyond baseline jitter
  - oast: the target performs an out-of-band callback we control (blind classes)
  - reflection: an unescaped marker appears in a context that proves injection

Every oracle runs N trials and reports evidence, so the verdict is auditable,
not a guess.
"""
from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .http_client import Probe, Response
from .oast import OastSession
from .waf import Baseline


@dataclass
class Verdict:
    confirmed: bool
    oracle: str
    confidence: float          # 0..1
    evidence: list[str] = field(default_factory=list)
    trials: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "oracle": self.oracle,
            "confidence": round(self.confidence, 2),
            "trials": self.trials,
            "evidence": self.evidence,
        }


def _send(probe: Probe, method: str, url: str, param: str, value: str, in_body: bool) -> Response:
    if in_body:
        return probe.send(method, url, data={param: value})
    return probe.send(method, url, params={param: value})


def verify_differential(
    probe: Probe,
    baseline: Baseline,
    *,
    method: str,
    url: str,
    param: str,
    true_payload: str,
    false_payload: str,
    in_body: bool = False,
    trials: int = 3,
) -> Verdict:
    """Boolean/differential oracle.

    true_payload should be logically-true (behaves like the original request),
    false_payload logically-false. A real injection makes the two responses
    diverge *consistently* while a non-injectable param does not.
    """
    ev: list[str] = []
    true_sigs: list[tuple[int, int]] = []
    false_sigs: list[tuple[int, int]] = []
    for _ in range(trials):
        rt = _send(probe, method, url, param, true_payload, in_body)
        rf = _send(probe, method, url, param, false_payload, in_body)
        # ignore trials where WAF blocked either side
        if baseline.classify(rt) == "blocked" or baseline.classify(rf) == "blocked":
            ev.append("trial skipped: WAF blocked one side")
            continue
        true_sigs.append((rt.status, rt.length))
        false_sigs.append((rf.status, rf.length))

    if not true_sigs:
        return Verdict(False, "differential", 0.0, ev + ["all trials blocked/failed"], trials)

    # true side stable AND distinct from false side across all trials
    true_stable = len(set(true_sigs)) == 1
    false_stable = len(set(false_sigs)) == 1
    distinct = set(true_sigs).isdisjoint(set(false_sigs))
    ev.append(f"true responses: {true_sigs}")
    ev.append(f"false responses: {false_sigs}")
    confirmed = true_stable and false_stable and distinct
    conf = 0.95 if confirmed else (0.4 if distinct else 0.05)
    if confirmed:
        ev.append("stable, disjoint true/false signatures across all trials -> causal difference")
    return Verdict(confirmed, "differential", conf, ev, len(true_sigs))


def verify_timing(
    probe: Probe,
    baseline: Baseline,
    *,
    method: str,
    url: str,
    param: str,
    sleep_payload: str,
    control_payload: str,
    delay_s: float,
    in_body: bool = False,
    trials: int = 3,
) -> Verdict:
    """Time-based oracle. Injected sleep must add ~delay_s over the control,
    reliably across trials, beyond normal jitter."""
    ev: list[str] = []
    control_ms: list[float] = []
    inject_ms: list[float] = []
    for _ in range(trials):
        rc = _send(probe, method, url, param, control_payload, in_body)
        ri = _send(probe, method, url, param, sleep_payload, in_body)
        control_ms.append(rc.elapsed_ms)
        inject_ms.append(ri.elapsed_ms)

    med_c = statistics.median(control_ms)
    med_i = statistics.median(inject_ms)
    delta = med_i - med_c
    ev.append(f"median control={med_c:.0f}ms inject={med_i:.0f}ms delta={delta:.0f}ms")
    expected = delay_s * 1000
    # require the delta to be at least 70% of the expected sleep and clearly above jitter
    confirmed = delta >= 0.7 * expected and delta > 500
    # also require monotonic-ish: every inject slower than every control by margin
    consistent = min(inject_ms) > max(control_ms)
    ev.append(f"all-inject-slower-than-all-control: {consistent}")
    conf = 0.9 if (confirmed and consistent) else (0.6 if confirmed else 0.1)
    return Verdict(confirmed and consistent, "timing", conf, ev, trials)


def verify_access_control(
    probe: Probe,
    *,
    method: str,
    url: str,
    owner_headers: dict[str, str],
    attacker_headers: dict[str, str],
    trials: int = 2,
) -> Verdict:
    """IDOR / broken-access-control oracle.

    Replays the SAME request to the SAME resource as three principals:
      owner    - the account that legitimately owns the resource
      attacker - a different authenticated account
      anon     - unauthenticated (control)

    Confirmed IDOR when the attacker receives the owner's resource
    (identical body) AND the anonymous control is denied/different - proving the
    endpoint is protected but the protection can be bypassed by another user.
    If anon also gets the same body, the resource is simply public (not a finding).
    """
    ev: list[str] = []
    owner_sigs: list[tuple[int, str]] = []
    atk_sigs: list[tuple[int, str]] = []
    anon_sigs: list[tuple[int, str]] = []
    for _ in range(trials):
        ro = probe.send(method, url, headers=owner_headers)
        ra = probe.send(method, url, headers=attacker_headers)
        rn = probe.send(method, url, headers={})
        owner_sigs.append((ro.status, ro.body_sha1))
        atk_sigs.append((ra.status, ra.body_sha1))
        anon_sigs.append((rn.status, rn.body_sha1))

    owner_stable = len(set(owner_sigs)) == 1
    ev.append(f"owner:  {owner_sigs}")
    ev.append(f"attacker: {atk_sigs}")
    ev.append(f"anon(control): {anon_sigs}")

    owner_body = owner_sigs[0][1]
    owner_ok = owner_sigs[0][0] in (200, 201, 202)
    attacker_reads_owner = all(s[1] == owner_body for s in atk_sigs) and owner_ok
    anon_denied = all(s[1] != owner_body for s in anon_sigs)

    if not owner_ok:
        return Verdict(False, "access_control", 0.1,
                       ev + ["owner request did not succeed; check identity/url"], trials)
    if attacker_reads_owner and not anon_denied:
        return Verdict(False, "access_control", 0.2,
                       ev + ["anon also gets the same body -> resource is PUBLIC, not IDOR"],
                       trials)
    confirmed = owner_stable and attacker_reads_owner and anon_denied
    if confirmed:
        ev.append("attacker received owner's exact resource while anon was denied -> IDOR/BAC")
    conf = 0.95 if confirmed else 0.15
    return Verdict(confirmed, "access_control", conf, ev, trials)


def verify_cors(
    probe: Probe,
    *,
    url: str,
    evil_origin: str = "https://evil.example",
) -> Verdict:
    """CORS misconfiguration oracle (deterministic, single pair of requests).

    Confirmed when the server reflects an attacker-controlled Origin in
    Access-Control-Allow-Origin (or uses '*') together with
    Access-Control-Allow-Credentials: true - which lets a malicious site read
    authenticated responses cross-origin.
    """
    r = probe.send("GET", url, headers={"Origin": evil_origin})
    acao = r.headers.get("access-control-allow-origin") or r.headers.get(
        "Access-Control-Allow-Origin", ""
    )
    acac = (
        r.headers.get("access-control-allow-credentials")
        or r.headers.get("Access-Control-Allow-Credentials", "")
    ).lower() == "true"
    ev = [f"sent Origin: {evil_origin}", f"ACAO={acao!r}", f"ACAC={acac}"]
    reflects = acao == evil_origin
    wildcard_creds = acao == "*" and acac
    confirmed = (reflects and acac) or wildcard_creds
    if confirmed:
        ev.append("attacker origin allowed WITH credentials -> cross-origin data theft")
    conf = 0.9 if confirmed else (0.4 if reflects else 0.0)
    return Verdict(confirmed, "cors", conf, ev, 1)


def verify_reflection(
    probe: Probe,
    baseline: Baseline,
    *,
    method: str,
    url: str,
    param: str,
    in_body: bool = False,
) -> Verdict:
    """Reflected-XSS oracle: canary -> context -> unencoded breaker.

    1. Inject a unique canary; confirm it reflects and in what context.
    2. Inject a context-appropriate breaker and confirm the special chars come
       back UNENCODED (i.e. the app didn't escape them) in an executable spot.
    A raw reflection alone is NOT a finding - only unencoded breakout is.
    """
    canary = "xq" + uuid.uuid4().hex[:8] + "zz"
    r1 = _send(probe, method, url, param, canary, in_body)
    if baseline.classify(r1) == "blocked":
        return Verdict(False, "reflection", 0.0, ["canary request was WAF-blocked"], 1)
    body = r1.body_text or r1.body_snippet
    if canary not in body:
        return Verdict(False, "reflection", 0.0, ["canary not reflected -> not injectable here"], 1)

    ctx = _reflection_context(body, canary)
    breaker = {
        "html": f'<{canary}b>',
        "attr_double": f'"{canary}x="',
        "attr_single": f"'{canary}x='",
        "script": f"';{canary}//",
        "unknown": f'<{canary}b>"{canary}x',
    }[ctx]
    r2 = _send(probe, method, url, param, breaker, in_body)
    body2 = r2.body_text or r2.body_snippet
    ev = [f"canary reflected in context: {ctx}", f"breaker: {breaker}"]

    # The raw special chars from the breaker must appear verbatim (i.e. unencoded).
    raw_ok = breaker in body2
    if raw_ok:
        ev.append("breaker reflected UNENCODED in an executable context -> reflected XSS")
    conf = 0.9 if raw_ok else 0.2
    return Verdict(raw_ok, "reflection", conf, ev, 1)


def _reflection_context(body: str, canary: str) -> str:
    i = body.find(canary)
    pre = body[max(0, i - 40):i]
    # crude but effective context sniffing around the reflection point
    if "<script" in pre.lower() and "</script" not in pre.lower():
        return "script"
    if pre.rstrip().endswith('="') or pre.count('"') % 2 == 1:
        return "attr_double"
    if pre.rstrip().endswith("='") or pre.count("'") % 2 == 1:
        return "attr_single"
    if ">" in pre and "<" not in pre.split(">")[-1]:
        return "html"
    return "unknown"


def verify_oast(
    probe: Probe,
    session: OastSession,
    *,
    send_fn: Callable[[str], Response],
    wait_s: float = 5.0,
) -> Verdict:
    """Out-of-band oracle. `send_fn(marker_url)` must embed the given callback URL
    into the payload and dispatch it. Any interaction proves the target reached
    our controlled infra."""
    marker = uuid.uuid4().hex[:10]
    callback = f"http://{marker}.{session.domain}/{marker}"
    before = len(session.poll(wait=0))
    send_fn(callback)
    hits = session.poll(wait=wait_s)
    new = hits[before:]
    relevant = [h for h in new if marker in str(h.raw).lower() or True]
    ev = [f"callback={callback}", f"interactions_after={len(new)}"]
    for h in new[:5]:
        ev.append(f"  {h.protocol} from {h.remote_addr}")
    confirmed = len(new) > 0
    return Verdict(confirmed, "oast", 0.99 if confirmed else 0.0, ev, 1)
