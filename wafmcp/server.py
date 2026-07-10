"""wafmcp - a minimal, evidence-first MCP server for authorized WAF/web testing.

Five composable primitives instead of hundreds of scanners:
  waf_calibrate   - fingerprint WAF + learn normal/blocked baseline
  http_probe      - single WAF-aware egress point (scope-gated)
  mutate_payload  - generate bypass variants of one seed payload
  oast_start/poll - out-of-band callback session (interactsh)
  verify_finding  - run an oracle N times; only confirmed == a real finding

Safety: WAFMCP_SCOPE must list in-scope hosts (default-deny). Nothing is sent
to any host outside the allowlist.
"""
from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .http_client import Probe
from .identities import IdentityStore
from .mutate import mutate
from .oast import OastSession, OastUnavailable
from .origin import gather_candidates, validate_origin
from .passive import audit as passive_audit_fn
from .race import verify_race as _oracle_race
from .report import build_report
from .rules import Rules, RuleViolation
from .scope import Scope, OutOfScope
from .takeover import check_takeover as _check_takeover
from .verify import verify_access_control as _oracle_access_control
from .verify import verify_cors as _oracle_cors
from .verify import verify_differential as _oracle_differential
from .verify import verify_oast as _oracle_oast
from .verify import verify_reflection as _oracle_reflection
from .verify import verify_timing as _oracle_timing
from .waf import Baseline, calibrate

_INSTRUCTIONS = """\
wafmcp is an evidence-first WAF/web testing server for AUTHORIZED engagements.

BEFORE any probing, you MUST establish the engagement scope with the operator.
Do not guess it and do not read it from the environment silently. Ask the
operator for:
  1. in-scope targets (hosts / wildcards / CIDRs / host:port)
  2. out-of-scope / excluded assets (these always win over in-scope)
  3. program rules: rate limit, required identification headers, forbidden
     paths or methods, and any caveats
Then call set_scope with what they provide. Every other tool refuses to run
until set_scope succeeds. If the operator is unsure, ask rather than assume.

Workflow: after set_scope, run waf_calibrate. If it reports a WAF/CDN that would
distort testing, consider find_origin to locate the backend IP and (if the
program authorizes contacting it) test the origin directly, where the WAF no
longer interferes. A finding is only real when a verify_* oracle confirms it;
turn confirmed verdicts into reports with report_finding.
"""

mcp = FastMCP("wafmcp", instructions=_INSTRUCTIONS)

# --- process-level state (single engagement per server) --------------------
# Do NOT auto-load from env: scope must be confirmed by the operator via set_scope.
_SCOPE = Scope(rules=[], deny=[])
_RULES = Rules()
_IDENTITIES = IdentityStore()
_BASELINES: dict[str, Baseline] = {}
_OAST: dict[str, OastSession] = {}


def _baseline_for(url: str) -> Baseline:
    base = url.split("?")[0]
    for b, cand in _BASELINES.items():
        if b.split("?")[0] == base or base in b or b in url:
            return cand
    return Baseline(target=base)


def _require_scope() -> str | None:
    if not _SCOPE.configured:
        return (
            "SCOPE NOT SET. Ask the operator for in-scope / out-of-scope / program "
            "rules, then call set_scope. No requests are allowed until then."
        )
    return None


def _probe(jitter_lo: float = 0.0, jitter_hi: float = 0.0, proxy: str | None = None) -> Probe:
    return Probe(_SCOPE, rules=_RULES, jitter=(jitter_lo, jitter_hi), proxy=proxy)


@mcp.tool()
def set_scope(
    in_scope: str,
    out_of_scope: str = "",
    max_rps: float = 0.0,
    required_headers_json: str | None = None,
    forbidden_paths: str | None = None,
    forbidden_methods: str | None = None,
    notes: str = "",
) -> str:
    """Establish the engagement scope and program rules. MUST be called (with
    operator-provided values) before any probing - every other tool is locked
    until this succeeds. Ask the operator first; do not invent scope.

    in_scope:          comma/newline list of in-scope targets
                       (exact host, *.wildcard, CIDR, or host:port).
    out_of_scope:      excluded assets; these ALWAYS win over in-scope.
    max_rps:           client-side rate limit in requests/sec (0 = unlimited).
    required_headers_json: JSON object of identification headers the program
                       mandates, e.g. '{"X-Bug-Bounty":"my-handle"}'.
    forbidden_paths:   comma list of url substrings that must never be requested.
    forbidden_methods: comma list of disallowed HTTP methods (e.g. 'DELETE,PUT').
    notes:             free-text program caveats.
    """
    if not in_scope.strip():
        return "in_scope is required. Ask the operator which targets are in scope."
    _SCOPE.configure(in_scope, out_of_scope)
    req_headers = {}
    if required_headers_json:
        try:
            req_headers = json.loads(required_headers_json)
        except json.JSONDecodeError as e:
            return f"bad required_headers_json: {e}"
    _RULES.max_rps = max_rps
    _RULES.required_headers = req_headers
    _RULES.forbidden_paths = [p.strip() for p in (forbidden_paths or "").split(",") if p.strip()]
    _RULES.forbidden_methods = [m.strip() for m in (forbidden_methods or "").split(",") if m.strip()]
    _RULES.notes = notes
    return "Scope and rules set.\n" + _SCOPE.describe() + "\n" + _RULES.describe()


@mcp.tool()
def scope_status() -> str:
    """Show the current in-scope allowlist, out-of-scope exclusions, and program
    rules. All probing is default-deny and locked until set_scope is called."""
    return _SCOPE.describe() + "\n" + _RULES.describe()


@mcp.tool()
def waf_calibrate(base_url: str, jitter_hi: float = 0.0) -> str:
    """Verify the target is CLEAN before live testing: detect any layer in front
    of the app that could distort results - WAF, CDN, caching, rate limiting, or
    unstable responses (identical requests returning different bodies).

    Returns test_reliable=true only when nothing interferes, plus a verdict that
    tells you which oracle to trust. If interference is found, it explains how it
    would distort a finding (e.g. a cache serving a stale body, a WAF turning a
    real vuln into a block) and what to do. Also caches the baseline so
    verify_finding can tell blocked/normal/anomaly apart.

    base_url: full URL of a benign endpoint that echoes/accepts a `q` parameter.
    """
    if (g := _require_scope()):
        return g
    try:
        with _probe(0.0, jitter_hi) as p:
            bl = calibrate(p, base_url)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    _BASELINES[base_url] = bl
    return json.dumps(bl.summary(), indent=2)


@mcp.tool()
def http_probe(
    method: str,
    url: str,
    param: str | None = None,
    value: str | None = None,
    in_body: bool = False,
    header_json: str | None = None,
    jitter_hi: float = 0.0,
    proxy: str | None = None,
) -> str:
    """Send one WAF-aware HTTP request through the scope gate. Returns a
    normalized response (status, length, timing, body hash, WAF hints, and - if a
    baseline exists for this base_url - a classification of blocked/normal/anomaly).

    Only 'anomaly' responses are candidate findings; never report a 'blocked' as one.
    """
    if (g := _require_scope()):
        return g
    headers = {}
    if header_json:
        try:
            headers = json.loads(header_json)
        except json.JSONDecodeError as e:
            return f"bad header_json: {e}"
    try:
        with _probe(0.0, jitter_hi, proxy) as p:
            if param is not None:
                if in_body:
                    r = p.send(method, url, data={param: value or ""}, headers=headers)
                else:
                    r = p.send(method, url, params={param: value or ""}, headers=headers)
            else:
                r = p.send(method, url, headers=headers)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"

    out = r.brief()
    # attach classification if we have a baseline for the origin
    for base, bl in _BASELINES.items():
        if url.startswith(base.split("?")[0].rsplit("/", 1)[0]) or base in url:
            out["classification"] = bl.classify(r)
            break
    out["body_snippet"] = r.body_snippet
    return json.dumps(out, indent=2)


@mcp.tool()
def mutate_payload(
    payload: str, context: str = "url", techniques: str | None = None, limit: int = 12
) -> str:
    """Generate ordered WAF-bypass variants of ONE seed payload (stealthiest
    first). Supply the semantic payload you want to land; this returns transport/
    encoding variants to evade signature matching. `techniques` optionally
    comma-limits transforms (e.g. 'url_encode,sql_inline_comment').

    Pair with http_probe: try variants in order until classification flips from
    'blocked' to 'anomaly'.
    """
    techs = [t.strip() for t in techniques.split(",")] if techniques else None
    variants = mutate(payload, context=context, techniques=techs, limit=limit)
    return json.dumps(
        [{"payload": v.payload, "technique": v.technique} for v in variants], indent=2
    )


@mcp.tool()
def oast_start(server: str | None = None, token: str | None = None) -> str:
    """Start an out-of-band (interactsh) session and return a callback domain to
    embed in payloads for blind SSRF/RCE/SQLi/XXE. A callback hit is the strongest
    proof a blind finding is real. Requires interactsh-client on PATH."""
    try:
        sess = OastSession.start(server=server, token=token)
    except OastUnavailable as e:
        return f"OAST UNAVAILABLE: {e}"
    _OAST["default"] = sess
    return json.dumps({"callback_domain": sess.domain, "session": "default"})


@mcp.tool()
def oast_poll(session: str = "default", wait_s: float = 3.0) -> str:
    """Poll an OAST session for interactions (DNS/HTTP/SMTP callbacks). Any
    interaction means the target reached infrastructure we control."""
    sess = _OAST.get(session)
    if not sess:
        return "no such OAST session; call oast_start first"
    hits = sess.poll(wait=wait_s)
    return json.dumps(
        [{"protocol": h.protocol, "from": h.remote_addr, "ts": h.timestamp} for h in hits],
        indent=2,
    )


@mcp.tool()
def verify_finding(
    oracle: str,
    method: str,
    url: str,
    param: str,
    in_body: bool = False,
    true_payload: str | None = None,
    false_payload: str | None = None,
    sleep_payload: str | None = None,
    control_payload: str | None = None,
    delay_s: float = 5.0,
    trials: int = 3,
) -> str:
    """Run an oracle N times to CONFIRM a candidate is a real finding (kills
    false positives). Returns a verdict with auditable evidence.

    oracle='differential': needs true_payload + false_payload (boolean-based).
    oracle='timing':        needs sleep_payload + control_payload + delay_s.
    oracle='oast':          use oast_start + http_probe with the callback URL, then
                            oast_poll - this tool covers differential/timing; for
                            OAST correlate oast_poll interactions to your payload.

    A finding is only real when confirmed==true.
    """
    if (g := _require_scope()):
        return g
    base = url.split("?")[0]
    bl = None
    for b, cand in _BASELINES.items():
        if b.split("?")[0] == base or base in b or b in url:
            bl = cand
            break
    if bl is None:
        bl = Baseline(target=base)  # empty baseline: classify() falls back sanely

    try:
        with _probe() as p:
            if oracle == "differential":
                if not (true_payload and false_payload):
                    return "differential oracle needs true_payload and false_payload"
                v = _oracle_differential(
                    p, bl, method=method, url=url, param=param,
                    true_payload=true_payload, false_payload=false_payload,
                    in_body=in_body, trials=trials,
                )
            elif oracle == "timing":
                if not (sleep_payload and control_payload):
                    return "timing oracle needs sleep_payload and control_payload"
                v = _oracle_timing(
                    p, bl, method=method, url=url, param=param,
                    sleep_payload=sleep_payload, control_payload=control_payload,
                    delay_s=delay_s, in_body=in_body, trials=trials,
                )
            else:
                return f"unknown oracle {oracle!r}; use 'differential' or 'timing'"
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(v.to_dict(), indent=2)


@mcp.tool()
def set_identity(name: str, headers_json: str | None = None, cookie: str | None = None) -> str:
    """Register a named authenticated session for access-control testing.
    Provide either headers_json (e.g. '{"Authorization":"Bearer ..."}') and/or a
    raw Cookie string. Use two identities (e.g. 'owner', 'attacker') plus the
    implicit anonymous control to test IDOR via verify_access_control."""
    headers = {}
    if headers_json:
        try:
            headers = json.loads(headers_json)
        except json.JSONDecodeError as e:
            return f"bad headers_json: {e}"
    ident = _IDENTITIES.set(name, headers, cookie)
    return f"identity {name!r} set with headers: {list(ident.headers) or '(anonymous)'}"


@mcp.tool()
def verify_access_control(
    method: str, url: str, owner: str, attacker: str, trials: int = 2
) -> str:
    """IDOR / broken-access-control oracle. Replays the same request to the same
    resource as `owner`, `attacker`, and anonymous, then confirms a finding only
    when the attacker receives the owner's exact resource while anon is denied.
    `owner` and `attacker` are identity names from set_identity."""
    if (g := _require_scope()):
        return g
    try:
        oh = _IDENTITIES.get(owner).headers
        ah = _IDENTITIES.get(attacker).headers
    except KeyError as e:
        return str(e)
    try:
        with _probe() as p:
            v = _oracle_access_control(
                p, method=method, url=url,
                owner_headers=oh, attacker_headers=ah, trials=trials,
            )
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(v.to_dict(), indent=2)


@mcp.tool()
def verify_oast(
    method: str,
    url: str,
    param: str,
    payload_template: str,
    in_body: bool = False,
    session: str = "default",
    wait_s: float = 6.0,
) -> str:
    """Blind vuln oracle (SSRF/RCE/XXE/blind SQLi) via out-of-band callback.
    payload_template must contain the literal token {OAST}; it is replaced with a
    unique callback URL, sent, then interactsh is polled. Any interaction confirms
    the target reached infrastructure we control. Call oast_start first."""
    if (g := _require_scope()):
        return g
    sess = _OAST.get(session)
    if not sess:
        return "no active OAST session; call oast_start first"
    if "{OAST}" not in payload_template:
        return "payload_template must contain the token {OAST}"

    try:
        with _probe() as p:
            def send_fn(callback: str):
                payload = payload_template.replace("{OAST}", callback)
                if in_body:
                    return p.send(method, url, data={param: payload})
                return p.send(method, url, params={param: payload})

            v = _oracle_oast(p, sess, send_fn=send_fn, wait_s=wait_s)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(v.to_dict(), indent=2)


@mcp.tool()
def check_cors(url: str, evil_origin: str = "https://evil.example") -> str:
    """CORS misconfiguration oracle. Confirms a finding when the server reflects
    an attacker-controlled Origin (or '*') together with
    Access-Control-Allow-Credentials: true - enabling cross-origin theft of
    authenticated data."""
    if (g := _require_scope()):
        return g
    try:
        with _probe() as p:
            v = _oracle_cors(p, url=url, evil_origin=evil_origin)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(v.to_dict(), indent=2)


@mcp.tool()
def verify_reflection(method: str, url: str, param: str, in_body: bool = False) -> str:
    """Reflected-XSS oracle: injects a unique canary, detects the reflection
    context (html/attribute/script), then confirms the context breaker comes back
    UNENCODED. A plain reflection is NOT reported - only unencoded breakout is."""
    if (g := _require_scope()):
        return g
    bl = _baseline_for(url)
    try:
        with _probe() as p:
            v = _oracle_reflection(p, bl, method=method, url=url, param=param, in_body=in_body)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(v.to_dict(), indent=2)


@mcp.tool()
def passive_audit(url: str, identity: str | None = None) -> str:
    """Zero-attack passive check on one response: missing security headers, weak
    cookie flags (HttpOnly/Secure/SameSite), and leaked secrets (API keys, JWTs,
    private keys). Optionally send as a named identity. Signal, not confirmed
    findings - but a leaked live key is real."""
    if (g := _require_scope()):
        return g
    headers = {}
    if identity:
        try:
            headers = _IDENTITIES.get(identity).headers
        except KeyError as e:
            return str(e)
    try:
        with _probe() as p:
            r = p.send("GET", url, headers=headers)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(passive_audit_fn(r).to_dict(), indent=2)


@mcp.tool()
def report_finding(
    title: str,
    severity: str,
    url: str,
    verdict_json: str,
    method: str = "GET",
    param: str | None = None,
    value: str | None = None,
    in_body: bool = False,
    headers_json: str | None = None,
    impact: str = "",
    notes: str = "",
) -> str:
    """Turn a CONFIRMED verdict into a submittable markdown PoC (curl repro +
    evidence + impact). verdict_json is the JSON returned by a verify_* tool;
    the report is REFUSED unless it shows confirmed=true. severity: critical|
    high|medium|low|info."""
    try:
        verdict = json.loads(verdict_json)
    except json.JSONDecodeError as e:
        return f"bad verdict_json: {e}"
    headers = {}
    if headers_json:
        try:
            headers = json.loads(headers_json)
        except json.JSONDecodeError as e:
            return f"bad headers_json: {e}"
    return build_report(
        title=title, severity=severity, url=url, method=method, param=param,
        value=value, in_body=in_body, headers=headers, verdict=verdict,
        impact=impact, notes=notes,
    )


@mcp.tool()
def find_origin(
    hostname: str,
    scheme: str = "http",
    use_crtsh: bool = True,
    validate: bool = True,
) -> str:
    """Discover the ORIGIN server IP behind a WAF/CDN, so the backend can be
    tested directly without the WAF distorting results.

    Passive recon (CT logs + subdomain DNS) gathers candidate IPs, excluding
    known CDN ranges. Each candidate is then CONFIRMED only by connecting straight
    to it with the target's Host header and matching the through-CDN baseline - a
    DNS record alone is never treated as the origin.

    Direct validation touches the candidate IP, so that IP must be in scope. Any
    candidate not in scope is returned unvalidated with a note to add it via
    set_scope IF the program authorizes it.

    Returns confirmed origins, candidates, and concrete next_steps.
    """
    if (g := _require_scope()):
        return g
    # baseline through the CDN (hostname itself must be in scope)
    try:
        with _probe() as p:
            baseline = p.send("GET", f"{scheme}://{hostname}/")
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"

    candidates = gather_candidates(hostname, use_crtsh=use_crtsh)
    if not candidates:
        return json.dumps({
            "hostname": hostname,
            "confirmed_origins": [],
            "candidates": [],
            "note": "No non-CDN candidate IPs found via CT logs or subdomain DNS. "
                    "The origin may be well hidden; consider SPF/MX records, favicon "
                    "hash search (Shodan/Censys), or historical passive DNS.",
        }, indent=2)

    confirmed = []
    listed = []
    if validate:
        with _probe() as p:
            for ip, cand in candidates.items():
                # only direct-connect if the IP is in scope; else just list it
                if not _SCOPE.rules:
                    cand.in_scope = False
                else:
                    try:
                        _SCOPE.check(f"{scheme}://{ip}/")
                        cand.in_scope = True
                    except OutOfScope:
                        cand.in_scope = False
                if cand.in_scope:
                    validate_origin(p, hostname, cand, baseline, scheme=scheme)
                else:
                    cand.evidence.append("not in scope - add to set_scope if authorized, then re-run")
                (confirmed if cand.confirmed else listed).append(cand.to_dict())

    out = {
        "hostname": hostname,
        "confirmed_origins": [c["ip"] for c in confirmed],
        "confirmed_detail": confirmed,
        "candidates": listed,
        "next_steps": _origin_next_steps(hostname, confirmed, listed),
    }
    return json.dumps(out, indent=2)


def _origin_next_steps(hostname: str, confirmed: list, listed: list) -> list[str]:
    if confirmed:
        ip = confirmed[0]["ip"]
        return [
            f"1. Origin CONFIRMED at {ip}. Re-run waf_calibrate against "
            f"http://{ip}/ (send Host: {hostname}) to verify it is now WAF-free "
            "(expect test_reliable=true / no WAF vendor).",
            f"2. Re-test any payloads that were 'blocked' through the CDN by pointing "
            f"http_probe at http://{ip}/<path> with header_json "
            f'{{"Host": "{hostname}"}} - the WAF no longer sees this traffic.',
            "3. If a finding only reproduces against the origin, note in the report "
            "that the origin is directly reachable (a finding in itself: WAF bypass / "
            "origin exposure) and include the Host-header curl repro.",
            "4. Keep using the confirmed IP for all subsequent oracles "
            "(verify_*, check_cors, etc.) so the WAF stops interfering.",
        ]
    if listed:
        pend = [c["ip"] for c in listed if not c["in_scope"]]
        steps = [
            "No origin confirmed yet. Candidate IPs were found but not validated.",
        ]
        if pend:
            steps.append(
                f"These candidates are OUT OF SCOPE and were not contacted: {pend}. "
                "If the program authorizes them, add them via set_scope and re-run find_origin."
            )
        steps.append(
            "Otherwise broaden discovery: check MX/SPF records for mail hosts on the "
            "same infra, search Shodan/Censys by favicon or TLS-cert hash, or query "
            "historical passive DNS for A records predating the CDN."
        )
        return steps
    return ["No candidates found."]


@mcp.tool()
def check_takeover(host: str, scheme: str = "https") -> str:
    """Subdomain takeover oracle. Resolves the host's CNAME chain, and if it
    points at a takeover-prone third-party service (GitHub Pages, S3, Heroku,
    Azure, etc.), fetches the page and confirms only when the service's known
    'unclaimed / no such site' fingerprint is present. A dangling CNAME alone is
    not reported. Returns verdict, evidence, and next_steps (how to PoC safely)."""
    if (g := _require_scope()):
        return g
    try:
        with _probe() as p:
            res = _check_takeover(p, host, scheme=scheme)
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    return json.dumps(res.to_dict(), indent=2)


@mcp.tool()
def verify_race(
    method: str,
    url: str,
    concurrency: int,
    expected_max: int,
    success_status: int = 200,
    success_marker: str | None = None,
    param: str | None = None,
    value: str | None = None,
    in_body: bool = False,
    header_json: str | None = None,
) -> str:
    """Race-condition oracle. Fires `concurrency` identical requests released
    simultaneously (barrier-synced to cross the check-then-act window together)
    and confirms a finding when the number of successes exceeds expected_max.

    Use for single-use coupons, one-per-account limits, balance withdrawals, etc.
    - success_status / success_marker: what a granted action looks like.
    - expected_max: the legitimate ceiling (e.g. 1 for a single-use coupon).
    The rate limit is bypassed for the burst (a limit would hide the bug); scope
    and forbidden method/path rules still apply. Keep concurrency modest (<=50).
    """
    if (g := _require_scope()):
        return g
    headers = {}
    if header_json:
        try:
            headers = json.loads(header_json)
        except json.JSONDecodeError as e:
            return f"bad header_json: {e}"
    params = data = None
    if param is not None:
        if in_body:
            data = {param: value or ""}
        else:
            params = {param: value or ""}

    p = _probe()
    try:
        v = _oracle_race(
            p, method=method, url=url, concurrency=concurrency,
            expected_max=expected_max, success_status=success_status,
            success_marker=success_marker, params=params, headers=headers, data=data,
        )
    except OutOfScope as e:
        return f"OUT OF SCOPE: {e}"
    except RuleViolation as e:
        return f"RULE VIOLATION: {e}"
    finally:
        p.close()
    return json.dumps(v.to_dict(), indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
