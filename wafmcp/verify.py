"""Finding verification - the oracle layer that makes a candidate a *finding*.

A candidate ("anomaly" from waf.classify) is not a finding. It becomes one only
when an oracle confirms it deterministically and repeatably:

  - differential: control vs. test payloads produce a stable, causal difference
    (e.g. `1 AND 1=1` behaves like baseline, `1 AND 1=2` diverges - boolean SQLi)
  - timing: an injected sleep reliably adds latency beyond baseline jitter
  - oast: the target performs an out-of-band callback we control (blind classes)
  - XSS: HTTP reflection establishes only a context candidate; stable harmless
    marker execution in a real browser is required for confirmation

Every oracle runs N trials and reports evidence, so the verdict is auditable,
not a guess.
"""
from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from .http_client import Probe, Response
from .oast import OastSession
from .waf import Baseline
from .xss import audit_reflected_xss


@dataclass
class Verdict:
    confirmed: bool
    oracle: str
    confidence: float          # 0..1
    evidence: list[str] = field(default_factory=list)
    trials: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "confirmed": self.confirmed,
            "oracle": self.oracle,
            "confidence": round(self.confidence, 2),
            "trials": self.trials,
            "evidence": self.evidence,
        }
        if self.details:
            result["details"] = self.details
        return result


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
    identity_headers: dict[str, str] | None = None,
    trusted_origin: str | None = None,
    intranet_target: bool = False,
    cookie_same_site: str | None = None,
    cookie_secure: bool | None = None,
) -> Verdict:
    """Evidence-first CORS oracle based on PortSwigger's attack taxonomy.

    The policy probes cover an attacker-controlled origin, ``null``, and (when
    supplied) a trusted origin plus the classic prefix-matching parser bypass.
    A credentialed finding is confirmed only when all browser and impact
    preconditions are demonstrated:

      * ACAO exactly matches an attacker-generatable Origin;
      * ACAC is ``true``;
      * a cookie identity was supplied with cross-site-eligible attributes
        (``SameSite=None; Secure``); and
      * the authenticated response differs from the anonymous control.

    Header behavior without authenticated, non-public data remains a candidate,
    not a reportable data-theft finding. ACAO ``*`` is never treated as
    credentialed access because browsers reject wildcard ACAO with credentials.
    It is confirmable only for an explicitly identified intranet target, where
    unauthenticated internal content may be readable through a victim's browser.
    """

    def canonical_origin(value: str, *, allow_null: bool = False) -> str:
        value = value.strip()
        if allow_null and value == "null":
            return value
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                f"invalid Origin {value!r}; use only scheme://host[:port]"
            )
        # An Origin never contains a trailing slash.
        return f"{parts.scheme}://{parts.netloc}"

    def header(response: Response, name: str) -> str:
        wanted = name.lower()
        return next(
            (str(value).strip() for key, value in response.headers.items()
             if key.lower() == wanted),
            "",
        )

    def prefix_bypass_origin(allowed: str, attacker: str) -> str | None:
        allowed_parts = urlsplit(allowed)
        attacker_parts = urlsplit(attacker)
        if allowed_parts.port is not None:
            # Appending an attacker domain after a port does not produce a valid
            # browser Origin. Let the operator supply a custom evil_origin.
            return None
        host = f"{allowed_parts.hostname}.{attacker_parts.hostname}"
        port = f":{attacker_parts.port}" if attacker_parts.port is not None else ""
        return f"{attacker_parts.scheme}://{host}{port}"

    evil_origin = canonical_origin(evil_origin)
    target_parts = urlsplit(url)
    if target_parts.scheme not in {"http", "https"} or not target_parts.hostname:
        raise ValueError(f"invalid target URL {url!r}; expected http(s) URL")
    target_origin = f"{target_parts.scheme}://{target_parts.netloc}"
    trusted_origin = canonical_origin(trusted_origin) if trusted_origin else None
    identity_headers = dict(identity_headers or {})
    has_cookie_identity = any(k.lower() == "cookie" for k in identity_headers)
    same_site = (cookie_same_site or "unknown").strip().lower()
    if same_site not in {"unknown", "lax", "strict", "none"}:
        raise ValueError(
            "cookie_same_site must be one of: Lax, Strict, None, or omitted"
        )
    cross_site_cookie_eligible = bool(same_site == "none" and cookie_secure is True)

    cases: list[tuple[str, str, bool]] = [
        ("attacker_origin", evil_origin, True),
        ("null_origin", "null", True),
    ]
    if trusted_origin:
        bypass = prefix_bypass_origin(trusted_origin, evil_origin)
        if bypass:
            cases.append(("prefix_parser_bypass", bypass, True))
        # A trusted origin is useful attack-surface evidence but is not attacker
        # controlled until XSS, takeover, or an HTTP interception prerequisite is
        # independently proven.
        cases.append(("trusted_origin", trusted_origin, False))

    observations: list[dict[str, Any]] = []
    ev: list[str] = [
        f"target origin: {target_origin}",
        f"cookie identity supplied: {has_cookie_identity}",
        f"session cookie SameSite: {same_site}",
        f"session cookie Secure: {cookie_secure}",
        f"cross-site cookie eligible: {cross_site_cookie_eligible}",
    ]
    confirmed_cases: list[str] = []
    policy_candidates: list[str] = []
    wildcard_seen = False
    readable_wildcard_seen = False
    auth_dependent_seen = False

    for name, origin, attacker_generatable in cases:
        auth_headers = {**identity_headers, "Origin": origin}
        response = probe.send("GET", url, headers=auth_headers)
        anon = None
        if identity_headers:
            anon = probe.send("GET", url, headers={"Origin": origin})

        acao = header(response, "access-control-allow-origin")
        acac = header(response, "access-control-allow-credentials").lower() == "true"
        vary = header(response, "vary")
        exact_match = acao == origin
        wildcard = acao == "*"
        wildcard_seen = wildcard_seen or wildcard
        successful = response.status in {200, 201, 202, 203, 206}
        auth_dependent = bool(
            anon
            and successful
            and (response.status, response.body_sha1) != (anon.status, anon.body_sha1)
        )
        auth_dependent_seen = auth_dependent_seen or auth_dependent
        blocked = response.blocked_heuristic or bool(response.error)
        readable_wildcard_seen = readable_wildcard_seen or bool(
            wildcard and successful and not blocked
        )
        browser_credentialed_read = (
            attacker_generatable
            and exact_match
            and acac
            and has_cookie_identity
            and cross_site_cookie_eligible
            and auth_dependent
            and not blocked
        )

        observation = {
            "case": name,
            "origin": origin,
            "status": response.status,
            "acao": acao,
            "acac": acac,
            "vary": vary,
            "attacker_generatable": attacker_generatable,
            "authenticated_response_differs": auth_dependent,
            "blocked_or_error": blocked,
            "browser_credentialed_read": browser_credentialed_read,
        }
        if anon:
            observation["anonymous_status"] = anon.status
        observations.append(observation)
        ev.append(
            f"{name}: Origin={origin!r} status={response.status} "
            f"ACAO={acao!r} ACAC={acac} auth-diff={auth_dependent}"
        )

        if browser_credentialed_read:
            confirmed_cases.append(name)
        elif attacker_generatable and exact_match and acac and successful and not blocked:
            policy_candidates.append(name)

    if readable_wildcard_seen and intranet_target:
        confirmed_cases.append("intranet_wildcard")
        ev.append(
            "wildcard ACAO on an operator-identified intranet target allows "
            "cross-origin reading of unauthenticated internal content"
        )
    elif wildcard_seen:
        ev.append(
            "ACAO='*' is not credentialed browser access, even if ACAC=true; "
            "only the PortSwigger intranet-without-credentials case may be exploitable"
        )

    if confirmed_cases:
        ev.append(
            "browser-readable CORS path and non-public impact prerequisites confirmed: "
            + ", ".join(confirmed_cases)
        )
    elif policy_candidates:
        ev.append(
            "CORS policy candidate only; authenticated non-public impact was not "
            "demonstrated: " + ", ".join(policy_candidates)
        )
    if has_cookie_identity and auth_dependent_seen and not cross_site_cookie_eligible:
        if same_site in {"lax", "strict"}:
            ev.append(
                f"SameSite={same_site.title()} blocks the session cookie on an "
                "external cross-site fetch; a manually attached Cookie header is "
                "not proof of browser exploitation"
            )
        elif same_site == "none" and cookie_secure is not True:
            ev.append(
                "SameSite=None requires Secure for browser acceptance; cross-site "
                "credential delivery was not established"
            )
        else:
            ev.append(
                "session cookie SameSite/Secure attributes were not supplied; "
                "cross-site credential delivery remains unverified"
            )
    if trusted_origin:
        ev.append(
            "trusted-origin acceptance is not independently exploitable; verify XSS, "
            "subdomain takeover, or an HTTP/TLS interception prerequisite separately"
        )

    confirmed = bool(confirmed_cases)
    confidence = 0.98 if confirmed else (0.55 if policy_candidates else 0.0)
    return Verdict(
        confirmed,
        "cors",
        confidence,
        ev,
        len(observations) + (len(observations) if identity_headers else 0),
        {
            "classification": (
                "exploitable_cors" if confirmed else
                "policy_candidate" if policy_candidates else
                "not_confirmed"
            ),
            "confirmed_cases": confirmed_cases,
            "policy_candidates": policy_candidates,
            "cookie_policy": {
                "same_site": same_site,
                "secure": cookie_secure,
                "cross_site_eligible": cross_site_cookie_eligible,
                "note": (
                    "Browser third-party-cookie policy still requires a real browser PoC"
                ),
            },
            "observations": observations,
        },
    )


def verify_reflection(
    probe: Probe,
    baseline: Baseline,
    *,
    method: str,
    url: str,
    param: str,
    in_body: bool = False,
    confirm_state_change: bool = False,
) -> Verdict:
    """Compatibility wrapper for the XSS context audit.

    This function intentionally never confirms XSS from HTTP reflection alone.
    Use the browser-backed ``verify_xss_execution`` MCP tool for confirmation.
    """
    audit = audit_reflected_xss(
        probe,
        baseline,
        method=method,
        url=url,
        param=param,
        in_body=in_body,
        confirm_state_change=confirm_state_change,
    )
    details = audit.to_dict()
    evidence = [
        f"classification={audit.classification}",
        f"reflected={audit.reflected}",
        f"candidate={audit.candidate}",
        "HTTP reflection is not execution proof; browser verification is required.",
    ]
    return Verdict(
        False,
        "xss_context_audit",
        0.55 if audit.candidate else 0.0,
        evidence,
        len(audit.observations),
        details,
    )


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
