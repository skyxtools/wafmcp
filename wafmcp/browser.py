"""Headless browser inspection for iframe / client-side testing.

Some targets only exist in a real browser context: a proxy iframe injected by
JavaScript (e.g. Viator's gtm-orn.viator.com), DataDome-gated pages that block
plain HTTP clients, DOM-based XSS, postMessage handlers. curl/httpx can't reach
any of that. This module drives a real Chromium via Playwright.

Playwright is a required wafmcp dependency. The Chromium runtime is installed
with `wafmcp install-browser`; if it is missing, browser tools return a clear
environment-specific install hint.

browser_inspect(url) renders the page and returns the signals that matter for
iframe security:
  - framing: X-Frame-Options / CSP frame-ancestors, and whether the page is
    embeddable by an attacker (clickjacking / frame-based attacks)
  - iframes: every <iframe> that ended up in the DOM (src/name/sandbox) - this is
    how you actually catch a JS-injected proxy iframe
  - postMessage: how many message listeners registered, and any messages seen
    (surface for postMessage-based XSS / origin-check bypass)
  - storage: localStorage/sessionStorage keys (tokens leaking client-side)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scope import Scope


class BrowserUnavailable(Exception):
    pass


def browser_install_hint() -> str:
    return (
        "Run `wafmcp install-browser` to install Chromium for this wafmcp "
        "environment. If system packages are missing, retry with "
        "`wafmcp install-browser --with-deps`."
    )


def format_browser_exception(exc: Exception) -> str:
    message = f"{type(exc).__name__}: {exc}"
    lowered = message.lower()
    missing_runtime_markers = (
        "executable doesn't exist",
        "browser has not been installed",
        "please run the following command",
        "playwright install",
        "host system is missing dependencies",
    )
    if any(marker in lowered for marker in missing_runtime_markers):
        return f"{message}\n{browser_install_hint()}"
    return message


def _ensure_playwright():
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as e:
        raise BrowserUnavailable(
            "Playwright is missing from this wafmcp installation. Run "
            "`wafmcp update`, or reinstall wafmcp from the GitHub main archive. "
            f"Then run `wafmcp install-browser`. {browser_install_hint()}"
        ) from e
    return sync_playwright


# Injected before any page script runs: hook addEventListener('message', ...) so
# we can count listeners and capture messages the page receives.
_INIT_SCRIPT = r"""
(() => {
  window.__wafmcp = { pmListeners: 0, messages: [] };
  const origAdd = window.addEventListener;
  window.addEventListener = function(type, fn, opts) {
    if (type === 'message') {
      window.__wafmcp.pmListeners++;
    }
    return origAdd.call(this, type, fn, opts);
  };
  origAdd.call(window, 'message', (e) => {
    try {
      window.__wafmcp.messages.push({
        origin: e.origin,
        data: (typeof e.data === 'string') ? e.data.slice(0, 300)
              : JSON.stringify(e.data).slice(0, 300)
      });
    } catch (_) {}
  });
})();
"""


@dataclass
class BrowserReport:
    url: str
    final_url: str = ""
    status: int = 0
    title: str = ""
    framing_headers: dict[str, str] = field(default_factory=dict)
    frameable: bool | None = None
    frame_verdict: str = ""
    iframes: list[dict[str, Any]] = field(default_factory=list)
    pm_listener_count: int = 0
    pm_messages: list[dict[str, Any]] = field(default_factory=list)
    storage_keys: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title,
            "framing_headers": self.framing_headers,
            "frameable_by_attacker": self.frameable,
            "frame_verdict": self.frame_verdict,
            "iframes": self.iframes,
            "postmessage_listeners": self.pm_listener_count,
            "postmessage_messages": self.pm_messages,
            "storage_keys": self.storage_keys,
            "error": self.error,
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps: list[str] = []
        if self.frameable:
            steps.append(
                "Page is embeddable by an attacker (no X-Frame-Options / no restrictive "
                "CSP frame-ancestors). If it has sensitive actions, this enables "
                "clickjacking - build a framing PoC."
            )
        interesting = [f for f in self.iframes if f.get("src")]
        if interesting:
            steps.append(
                f"{len(interesting)} iframe(s) present: {[f['src'] for f in interesting][:5]}. "
                "For a proxy iframe (e.g. gtm-orn), inspect it directly with browser_inspect "
                "on its src, and test postMessage handlers for missing origin checks."
            )
        if self.pm_listener_count:
            steps.append(
                f"{self.pm_listener_count} postMessage listener(s) registered. Test for "
                "origin-check bypass: send crafted messages from a foreign origin and see if "
                "the handler acts on them (postMessage XSS / state change)."
            )
        if not steps:
            steps.append("No framing weakness, iframe, or postMessage surface observed here.")
        return steps


def _frame_verdict(headers: dict[str, str]) -> tuple[bool, str]:
    low = {k.lower(): v for k, v in headers.items()}
    xfo = low.get("x-frame-options", "").upper()
    csp = low.get("content-security-policy", "").lower()
    fa = ""
    if "frame-ancestors" in csp:
        # extract the frame-ancestors directive
        for part in csp.split(";"):
            if "frame-ancestors" in part:
                fa = part.strip()
                break
    if xfo in ("DENY", "SAMEORIGIN"):
        return False, f"protected by X-Frame-Options: {xfo}"
    if fa:
        if "'none'" in fa or "'self'" in fa:
            return False, f"protected by CSP {fa}"
        return True, f"CSP frame-ancestors present but permissive: {fa}"
    return True, "no X-Frame-Options and no CSP frame-ancestors -> embeddable by any site"


def _parse_cookie_header(cookie: str, url: str) -> list[dict[str, Any]]:
    from urllib.parse import urlsplit
    host = urlsplit(url).hostname or ""
    # register on the registrable-ish parent so subdomains share it (e.g. datadome)
    domain = "." + ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    out = []
    for part in cookie.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out.append({"name": k.strip(), "value": v.strip(), "domain": domain, "path": "/"})
    return out


def browser_inspect(
    scope: Scope, url: str, wait_ms: int = 2500, timeout_ms: int = 30000,
    cookie: str | None = None, headless: bool = True,
) -> BrowserReport:
    """Render `url` in Chromium and report iframe-security signals.

    Navigation is scope-checked. `cookie` (a raw "k=v; k2=v2" string) is injected
    before navigation - use it to carry a manually-solved DataDome/session cookie
    past a bot wall. headless=False can also help against aggressive bot defenses.
    Raises BrowserUnavailable if the required Playwright package is missing."""
    scope.check(url)  # gate navigation like every other egress
    sync_playwright = _ensure_playwright()

    rep = BrowserReport(url=url)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless)
            ctx = browser.new_context(ignore_https_errors=True)
            if cookie:
                try:
                    ctx.add_cookies(_parse_cookie_header(cookie, url))
                except Exception as e:
                    rep.error = f"cookie inject failed: {e}"
            ctx.add_init_script(_INIT_SCRIPT)
            page = ctx.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(wait_ms)  # let JS inject iframes / register handlers

            if resp is not None:
                rep.status = resp.status
                rep.framing_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in ("x-frame-options", "content-security-policy",
                                     "content-type", "set-cookie")
                }
            rep.final_url = page.url
            rep.title = page.title()
            rep.frameable, rep.frame_verdict = _frame_verdict(rep.framing_headers)

            # iframes that actually made it into the DOM (incl. JS-injected)
            rep.iframes = page.evaluate(
                """() => Array.from(document.querySelectorAll('iframe')).map(f => ({
                    src: f.src || null, name: f.name || null,
                    sandbox: f.getAttribute('sandbox'),
                    id: f.id || null
                }))"""
            )
            hook = page.evaluate("() => window.__wafmcp || {pmListeners:0, messages:[]}")
            rep.pm_listener_count = hook.get("pmListeners", 0)
            rep.pm_messages = hook.get("messages", [])
            rep.storage_keys = page.evaluate(
                """() => ({
                    local: Object.keys(window.localStorage || {}),
                    session: Object.keys(window.sessionStorage || {})
                })"""
            )
            browser.close()
    except BrowserUnavailable:
        raise
    except Exception as e:
        rep.error = format_browser_exception(e)
    return rep
