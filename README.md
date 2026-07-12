# wafmcp

> ⚠️ **For education and authorized testing only.** Use `wafmcp` exclusively
> against systems you own or are **explicitly authorized** to test (your own labs,
> or a bug-bounty / pentest program whose scope and rules permit it). Testing
> systems without permission is illegal in most jurisdictions. This project is
> provided for educational and defensive-research purposes, **as-is and without
> warranty of any kind**. The authors accept **no liability** for any misuse or
> damage. By using this tool you take full responsibility for your actions and
> confirm you have authorization. See [Legal & Responsible Use](#legal--responsible-use).

Minimal, **evidence-first** MCP server for authorized WAF / web-app security testing.

The opposite of a 150-tool wrapper. Instead of hundreds of scanners that flood an
LLM with noise and false positives, `wafmcp` ships **five composable primitives**
and one rule: *a finding is only real when an oracle confirms it deterministically.*

WAF handling here is for **verification, not evasion**: before live testing a
bug-bounty target, you confirm nothing (WAF / CDN / cache / rate-limit) sits in
front of the app to distort your results. If a layer *is* present, the tool tells
you how it would skew a finding and which oracle to trust instead.

## Why this design

| Problem with big toolkits | wafmcp's answer |
|---|---|
| LLM drowns in tool choice | 5 primitives it composes itself |
| "status 500" reported as a bug | every finding needs an oracle (differential / timing / OAST) |
| WAF blocks reported as vulns | mandatory baseline calibration classifies blocked vs anomaly |
| thousands of hardcoded payloads | one seed payload + transform engine |

## The tools

- **`waf_calibrate`** — **reliability check, run first.** Confirms the target is
  *clean* before live testing: detects any layer that could distort results —
  WAF, CDN, caching, rate limiting, or unstable responses (identical requests
  returning different bodies). Returns `test_reliable: true/false` and a verdict
  saying which oracle to trust. In a bug-bounty context this answers the real
  question: *"will what I see during the live test reflect the backend, or a
  layer in front of it?"*
- **`http_probe`** — the single, scope-gated egress point. Returns status,
  timing, **response headers** (Location, Set-Cookie, Content-Type, CSP, …),
  body (snippet or `full_body`), WAF hints, and blocked/normal/anomaly
  classification. Sends proper request bodies (`json_body`, `form_json`,
  `raw_body`), can `follow_redirects` and shows the redirect chain, and can act
  as a saved `identity`.
- **`login_capture`** — log in once and capture the resulting session (Set-Cookie
  jar) into a named identity for all subsequent tools.
- **`extract_endpoints`** — parse links/forms/JS-paths out of a body you already
  fetched (parse-only, not a spider) to surface testable endpoints and params.
- **`wayback_urls`** — passive historical endpoint discovery through the
  Internet Archive CDX API. Uses host/domain matching, `collapse=urlkey`, date
  and status filters, hard result limits, and allow/deny scope filtering. It
  queries only the archive index and never visits a returned target URL.
- **`analyze_jwt`** — **PortSwigger-aligned offline JWT/JWS audit.** Separates
  offline-confirmed weak HMAC secrets from mutations that still require server
  acceptance. Emits controlled probes for ignored/arbitrary signatures,
  mixed-case `alg:none`, `kid` → `/dev/null`, and RS→HS confusion when the exact
  public key is supplied. Surfaces `jwk`/`jku`/`x5c`/`x5u`, duplicate JOSE keys,
  and claim-lifetime issues without misreporting header presence as a finding.
  Accepts optional custom secret wordlists and claim overrides; never contacts a
  target itself.
- **`audit_graphql`** — **[PortSwigger-aligned](https://portswigger.net/web-security/graphql),
  read-only GraphQL mapping.**
  Confirms an endpoint with `query{__typename}`, probes standard and
  whitespace-bypass introspection, suggestions, GET/form transports, two-item
  batching, and aliases. Optionally returns a bounded schema summary. Normal
  GraphQL features remain exposure/attack-surface signals rather than findings;
  the tool never executes a mutation.
- **`audit_api`** — **[PortSwigger-aligned](https://portswigger.net/web-security/api-testing),
  read-only REST API reconnaissance.** Maps one endpoint with GET/OPTIONS and
  checks a bounded, same-origin list of common OpenAPI, Swagger, and interactive
  documentation paths. Documentation exposure, advertised methods, and JSON
  responses are attack-surface signals, never findings by themselves.
- **`analyze_openapi`** — offline OpenAPI/Swagger JSON analysis. Summarizes
  servers, authentication schemes, operations, parameters, content types, and
  sensitive-looking schema fields without contacting the target.
- **`find_mass_assignment_candidates`** — offline object diff that identifies
  fields returned by a read response but absent from the application's intended
  update body. Results are hypotheses for reversible verification, not findings.
- **`probe_methods`** — which HTTP methods the endpoint accepts (PUT/DELETE/
  PATCH/TRACE) plus method-override header bypasses.
- **`verify_open_redirect`** — confirms a param that drives a redirect to an
  attacker-controlled host (Location oracle).
- **`verify_lfi`** — path traversal / local file include, confirmed by a file
  content signature (e.g. `root:x:0:0`), not just a status change.
- **`browser_inspect`** — *(opt-in, needs Playwright)* render a URL in a real
  headless Chromium and report client-side signals HTTP clients can't see:
  framing (X-Frame-Options / CSP frame-ancestors + frameable-by-attacker
  verdict), **iframes in the final DOM** (incl. JS-injected proxy iframes),
  postMessage listener count + observed messages, and localStorage/sessionStorage
  keys. Accepts a `cookie` string to carry a manually-solved bot-wall cookie
  (e.g. DataDome) and `headless=false`.

### Optional: browser module

```bash
pipx inject --include-apps wafmcp playwright
playwright install chromium
```

For a local editable development installation, use
`pip install -e ".[browser]"` instead.

The core toolkit needs neither Playwright nor a browser; `browser_inspect`
returns install instructions until they're present. Note: aggressive bot walls
(DataDome, etc.) can still challenge headless Chromium — solve the CAPTCHA once in
your own browser and pass the resulting cookie via `cookie=`.
- **`mutate_payload`** — generate ordered bypass variants of ONE seed payload
  (encoding, comments, case, unicode, whitespace), stealthiest first.
- **`oast_start` / `oast_poll`** — out-of-band callbacks via interactsh. A
  callback hit is the strongest proof a blind finding (SSRF/RCE/XXE/blind SQLi)
  is real.
- **`verify_finding`** — run an oracle N times and return an auditable verdict.
  `confirmed: true` is the only thing that counts as a finding.

### Bug-bounty oracles (each confirms a real, payable class)

- **`set_identity`** — register named authenticated sessions (`owner`,
  `attacker`, …) by header/cookie, for access-control testing.
- **`verify_access_control`** — **IDOR / broken access control.** Replays the
  same request as owner vs. attacker vs. anonymous; confirms only when the
  attacker receives the owner's exact resource while anon is denied (public
  resources are correctly rejected as non-findings).
- **`verify_graphql_access`** — **GraphQL IDOR/BOLA oracle.** Replays one exact
  read-only query and variables as owner, a different authenticated user, and
  anonymous. Confirms only when the attacker receives the owner's exact
  normalized GraphQL `data` while anonymous is denied. Mutations and
  subscriptions are refused.
- **`verify_api_sspp`** — **read-only server-side parameter pollution oracle.**
  Repeats baseline, direct override, encoded duplicate-parameter, truncation,
  and invalid-parameter controls. Confirms only when the injected duplicate
  deterministically matches the direct override and differs from baseline;
  parser errors and response differences alone remain candidates.
- **`verify_mass_assignment`** — **explicit, reversible state-change oracle.**
  Requires `confirm_state_change=true`, reads the original field value, submits
  one POST/PUT/PATCH candidate, verifies it with a fresh GET, then restores and
  re-verifies the original value. It never sends DELETE and confirms only when
  both the change and restoration succeed.
- **`verify_oast`** — **blind SSRF / RCE / XXE / blind SQLi.** Inject a
  `{OAST}` callback into your payload template; an interactsh interaction is the
  proof.
- **`check_cors`** — **evidence-first CORS verification aligned with
  PortSwigger.** Tests attacker-controlled and `null` origins, prefix-parser
  bypasses, trusted-origin relationships, and the unauthenticated intranet
  wildcard case. Credentialed impact is confirmed only with a saved cookie
  identity whose response differs from the anonymous control and whose supplied
  attributes permit cross-site delivery (`SameSite=None; Secure`). A manually
  attached Lax/Strict cookie remains a candidate, and `ACAO: *` is never
  misreported as credentialed browser access. A real-browser PoC is still needed
  to account for browser-level third-party-cookie blocking.
- **`verify_reflection`** — **reflected XSS.** Canary → context detection
  (html/attr/script) → confirms the breaker returns *unencoded*. A plain
  reflection is not reported.
- **`passive_audit`** — zero-attack signal from one response: missing security
  headers, weak cookie flags, and leaked secrets (AWS/Google/GitHub keys, JWTs,
  private keys).
- **`report_finding`** — turn a confirmed verdict into a **submittable markdown
  PoC** (curl repro + evidence + impact). Refuses to emit anything for an
  unconfirmed verdict.
- **`find_origin`** — locate the **origin IP behind a WAF/CDN** so the backend
  can be tested directly (where the WAF no longer interferes). Gathers candidates
  from certificate-transparency logs + subdomain DNS, excludes known CDN ranges,
  and **confirms** each candidate by direct-connecting with the target's Host
  header and matching the through-CDN baseline — a DNS record alone is never
  treated as the origin. Direct validation is scope-gated; out-of-scope
  candidates are listed but never contacted. Output includes concrete
  `next_steps` (re-calibrate against the IP, replay blocked payloads with a Host
  header, keep using the confirmed IP for all oracles).
- **`check_takeover`** — **subdomain takeover.** Resolves the host's CNAME chain;
  if it points at a takeover-prone service (GitHub Pages, S3, Heroku, Azure,
  Shopify, Fastly, …), fetches the page and confirms only when that service's
  known *unclaimed / no-such-site* fingerprint is present. A dangling CNAME alone
  is not reported. Returns verdict, evidence, and safe-PoC `next_steps`.
- **`verify_race`** — **race condition.** Fires N identical requests released
  *simultaneously* (a `threading.Barrier` makes them cross the check-then-act
  window together) and confirms a finding when the number of successes exceeds
  the operator-asserted legitimate ceiling (e.g. a single-use coupon that applies
  twice). The rate limit is bypassed for the burst (a limit would hide the bug);
  scope and forbidden method/path rules still apply.

## Safety: scope is confirmed with the operator, not guessed

The server does **not** read scope from the environment silently. Every probing
tool is **locked** until `set_scope` is called with operator-provided values. The
server instructions tell the agent to ask you first for:

1. **in-scope** targets — exact host, `*.wildcard`, CIDR, or `host:port`
2. **out-of-scope** exclusions — these **always win** over in-scope (an excluded
   asset is never contacted even if a wildcard also matches it)
3. **program rules** — rate limit, required identification headers, forbidden
   paths/methods, and any caveats

Example `set_scope` call the agent makes after asking you:

```jsonc
set_scope(
  in_scope        = "*.target.com, api.target.com, 10.0.0.0/24",
  out_of_scope    = "admin.target.com, *.corp.target.com",
  max_rps         = 5,
  required_headers_json = "{\"X-Bug-Bounty\": \"your-handle\"}",
  forbidden_paths = "/logout, /billing",
  forbidden_methods = "DELETE, PUT",
  notes           = "no automated scanning of the login flow"
)
```

Rules are enforced at the transport layer: the rate limit throttles every
request, mandated headers are injected, and forbidden methods/paths are hard-
blocked. **Only test systems you are authorized to test.**

## Install and update (no clone required)

Install the latest `main` branch directly from GitHub's source archive. This
does not require a local repository or even the `git` executable:

```bash
pipx install https://github.com/skyxtools/wafmcp/archive/refs/heads/main.zip
wafmcp --version
```

When a new change is published, update the existing installation in place:

```bash
wafmcp update
```

The update command upgrades the canonical `main` archive using pip's
`only-if-needed` dependency strategy, so dependencies are changed only when the
new release requires it. Every published change must bump the package version
for pip to recognize it as an upgrade. Restart the MCP client after the command
completes. For local development, clone the repository and use
`pip install -e ".[dev]"` instead.

For an automatically refreshed, ephemeral installation, use `uvx`. `--refresh`
checks the source archive again whenever the MCP process starts:

```bash
uvx --refresh --from https://github.com/skyxtools/wafmcp/archive/refs/heads/main.zip wafmcp
```

The persistent `pipx` installation is better for offline/reliable startup;
`uvx --refresh` trades startup time and network availability for automatic
updates.

## Run as an MCP server

### opencode

A ready `opencode.json` is included for local development. Users who do not
want a clone can launch the automatically refreshed GitHub version over stdio:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "wafmcp": {
      "type": "local",
      "command": [
        "uvx",
        "--refresh",
        "--from",
        "https://github.com/skyxtools/wafmcp/archive/refs/heads/main.zip",
        "wafmcp"
      ],
      "enabled": true
    }
  }
}
```

Put it in the project root (or merge the `mcp` block into `~/.config/opencode/
opencode.jsonc` for global use). On start, the agent is instructed to ask you
for scope/rules and call `set_scope` before anything else.

### Claude Code / generic

```json
{
  "mcpServers": {
    "wafmcp": {
      "command": "uvx",
      "args": [
        "--refresh",
        "--from",
        "https://github.com/skyxtools/wafmcp/archive/refs/heads/main.zip",
        "wafmcp"
      ]
    }
  }
}
```

### Out-of-band (interactsh) for blind findings

`oast_start` / `verify_oast` need `interactsh-client` on PATH:

```bash
# download the release binary for your OS from:
#   https://github.com/projectdiscovery/interactsh/releases
# (or, with Go:) go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -version   # confirm it runs
```

Verified working with interactsh-client v1.3.1 (public projectdiscovery servers).

## Typical LLM loop

0. `set_scope(...)` — the agent asks you for in-scope / out-of-scope / rules and
   sets them. Nothing else runs until this succeeds.
1. `waf_calibrate(base_url)` — learn baseline, see WAF vendor + block signature.
2. `http_probe(...)` a payload. If `classification == "blocked"`, call
   `mutate_payload(seed)` and retry variants until it flips to `"anomaly"`.
3. `verify_finding(oracle="differential", true_payload=..., false_payload=...)`
   — for blind classes, `oast_start` → embed callback via `http_probe` →
   `oast_poll`.
4. Report only verdicts where `confirmed == true`, attaching the evidence.

## Tests

```bash
pytest tests/                          # offline: scope, mutation, classify
PYTHONPATH=. python tests/smoke_live.py  # live end-to-end vs a local mock target
```

The live smoke test proves the full loop: baseline learned, an injectable param
**confirmed**, a non-injectable param **rejected** (no false positive), and an
out-of-scope host **blocked**.

## Legal & Responsible Use

**English.** `wafmcp` is intended **solely for educational purposes and for
authorized security testing.** You may use it **only** against systems you own or
for which you hold **explicit, written authorization** (for example, an in-scope
asset of a bug-bounty or penetration-testing engagement whose rules of engagement
permit the activity). Unauthorized access to, or testing of, computer systems is
illegal in most jurisdictions and may carry criminal and civil penalties.

The tool enforces a **default-deny scope allowlist** (`set_scope`) precisely so
that no request is ever sent to a host you have not explicitly authorized — but
that gate is a safety aid, **not** a substitute for obtaining proper permission.

This software is provided **"AS IS", without warranty of any kind**, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors
or contributors be liable for any claim, damages, or other liability**, whether
in an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or its use. **The authors accept no responsibility
whatsoever for any misuse.** By using `wafmcp`, you accept full and sole
responsibility for your actions and confirm that you have the necessary
authorization.

**Bahasa Indonesia.** `wafmcp` **hanya** ditujukan untuk **tujuan edukasi dan
pengujian keamanan yang berizin.** Gunakan **hanya** pada sistem milikmu sendiri
atau yang kamu miliki **izin tertulis secara eksplisit** untuk mengujinya
(misalnya aset yang masuk scope program bug bounty / pentest yang aturannya
mengizinkan). Mengakses atau menguji sistem tanpa izin adalah **ilegal** di
sebagian besar wilayah hukum dan dapat dikenai sanksi pidana maupun perdata.

Tool ini memberlakukan **allowlist scope default-deny** (`set_scope`) agar tidak
ada request yang terkirim ke host yang belum kamu izinkan — namun gerbang itu
hanyalah alat bantu keamanan, **bukan** pengganti izin yang sah.

Perangkat lunak ini disediakan **"SEBAGAIMANA ADANYA", tanpa jaminan apa pun.**
**Penulis tidak bertanggung jawab atas segala penyalahgunaan** maupun kerugian
yang timbul dari penggunaan tool ini. Dengan menggunakan `wafmcp`, kamu menerima
tanggung jawab penuh atas tindakanmu dan menyatakan telah memiliki otorisasi yang
diperlukan.
