"""PortSwigger-aligned, evidence-first XSS analysis and browser oracles.

HTTP reflection and dangerous characters are candidates, not proof. Reflected,
stored, and DOM XSS are confirmed only when a harmless per-run JavaScript marker
executes in a real browser. Payloads never read cookies or send network data.
"""
from __future__ import annotations

import html
import json
import re
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .browser import BrowserUnavailable, _ensure_playwright
from .http_client import Probe, Response, sanitize_headers
from .rules import Rules
from .scope import Scope
from .waf import Baseline


METHODOLOGY = "https://portswigger.net/web-security/cross-site-scripting"
CONTEXTS_REFERENCE = "https://portswigger.net/web-security/cross-site-scripting/contexts"
DOM_REFERENCE = "https://portswigger.net/web-security/cross-site-scripting/dom-based"
STORED_REFERENCE = "https://portswigger.net/web-security/cross-site-scripting/stored"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
_META_CHARS = "<>\"'`${}\\"
_URL_ATTRIBUTES = {"href", "src", "action", "formaction", "xlink:href", "data"}
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


def _header(response: Response, name: str) -> str:
    return next(
        (str(value) for key, value in response.headers.items() if key.lower() == name.lower()),
        "",
    )


def _send(
    probe: Probe,
    method: str,
    url: str,
    param: str,
    value: str,
    in_body: bool,
    identity_headers: dict[str, str] | None,
) -> Response:
    headers = dict(identity_headers or {})
    if in_body:
        return probe.send(method, url, headers=headers, data={param: value})
    return probe.send(method, url, headers=headers, params={param: value})


def _js_context(source: str, marker_index: int) -> str:
    quote_char: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < marker_index:
        char = source[index]
        nxt = source[index + 1] if index + 1 < marker_index else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            quote_char = char
        index += 1
    return {
        "'": "javascript_single_string",
        '"': "javascript_double_string",
        "`": "javascript_template_literal",
    }.get(quote_char, "javascript_code")


def _attribute_quote(raw_tag: str, marker: str) -> str:
    marker_index = raw_tag.find(marker)
    if marker_index < 0:
        return "unknown"
    prefix = raw_tag[:marker_index]
    equals = prefix.rfind("=")
    if equals < 0:
        return "unknown"
    value_prefix = prefix[equals + 1:].lstrip()
    if value_prefix.startswith('"'):
        return "double"
    if value_prefix.startswith("'"):
        return "single"
    return "unquoted"


class _ContextParser(HTMLParser):
    def __init__(self, marker: str) -> None:
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.stack: list[str] = []
        self.contexts: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        raw_tag = self.get_starttag_text() or ""
        for name, value in attrs:
            if value and self.marker in value:
                quote_type = _attribute_quote(raw_tag, self.marker)
                context = "html_attribute"
                if name.lower().startswith("on"):
                    context = "event_handler_attribute"
                elif name.lower() in _URL_ATTRIBUTES:
                    context = "url_attribute"
                self.contexts.append({
                    "context": context,
                    "tag": tag.lower(),
                    "attribute": name.lower(),
                    "quote": quote_type,
                })
        if tag.lower() not in _VOID_TAGS:
            self.stack.append(tag.lower())

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self.stack:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        low = tag.lower()
        if low in self.stack:
            reverse_index = self.stack[::-1].index(low)
            del self.stack[len(self.stack) - reverse_index - 1:]

    def handle_data(self, data: str) -> None:
        start = 0
        while True:
            index = data.find(self.marker, start)
            if index < 0:
                break
            if self.stack and self.stack[-1] == "script":
                self.contexts.append({"context": _js_context(data, index), "tag": "script"})
            elif self.stack and self.stack[-1] == "style":
                self.contexts.append({"context": "css_text", "tag": "style"})
            else:
                self.contexts.append({"context": "html_text", "tag": self.stack[-1] if self.stack else None})
            start = index + len(self.marker)

    def handle_comment(self, data: str) -> None:
        if self.marker in data:
            self.contexts.append({"context": "html_comment"})


def reflection_contexts(body: str, marker: str) -> list[dict[str, Any]]:
    """Identify every HTML/attribute/JavaScript reflection context."""
    parser = _ContextParser(marker)
    try:
        parser.feed(body)
    except Exception:
        pass
    if not parser.contexts and marker in body:
        return [{"context": "unknown_text"}]
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in parser.contexts:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _raw_meta_characters(body: str, canary: str) -> dict[str, bool]:
    return {
        char: f"{canary}{index}{char}" in body
        for index, char in enumerate(_META_CHARS)
    }


def _occurrences(value: str, needle: str) -> list[int]:
    indexes: list[int] = []
    start = 0
    while True:
        index = value.find(needle, start)
        if index < 0:
            return indexes
        indexes.append(index)
        start = index + len(needle)


def _context_candidate(context: dict[str, Any], raw: dict[str, bool]) -> tuple[bool, str]:
    name = context["context"]
    angle_breakout = raw.get("<", False) and raw.get(">", False)
    if name == "html_text":
        return angle_breakout, "raw angle brackets can introduce an HTML element"
    if name in {"html_attribute", "url_attribute", "event_handler_attribute"}:
        quote_type = context.get("quote")
        quote_breakout = (
            quote_type == "double" and raw.get('"', False)
        ) or (
            quote_type == "single" and raw.get("'", False)
        ) or quote_type == "unquoted"
        return bool(angle_breakout or quote_breakout), "attribute delimiter or tag breakout may be possible"
    if name == "javascript_single_string":
        return bool(raw.get("'", False) or angle_breakout), "single-quoted JavaScript string delimiter may be breakable"
    if name == "javascript_double_string":
        return bool(raw.get('"', False) or angle_breakout), "double-quoted JavaScript string delimiter may be breakable"
    if name == "javascript_template_literal":
        expression = raw.get("$", False) and raw.get("{", False) and raw.get("}", False)
        return bool(expression or raw.get("`", False) or angle_breakout), "template expression or delimiter may be injectable"
    if name == "javascript_code":
        return True, "input is reflected directly into JavaScript code; browser execution is required"
    return False, "no automatic executable context was established"


@dataclass
class XssAudit:
    url: str
    method: str
    parameter: str
    reflected: bool
    candidate: bool
    classification: str
    contexts: list[dict[str, Any]] = field(default_factory=list)
    raw_meta_characters: dict[str, bool] = field(default_factory=dict)
    candidate_reasons: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "contexts_reference": CONTEXTS_REFERENCE,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "reflected": self.reflected,
            "candidate": self.candidate,
            "confirmed": False,
            "classification": self.classification,
            "contexts": self.contexts,
            "raw_meta_characters": self.raw_meta_characters,
            "candidate_reasons": self.candidate_reasons,
            "observations": self.observations,
            "next_steps": (
                ["Run verify_xss_execution. PortSwigger treats arbitrary JavaScript execution in a browser as confirmation; raw reflection alone is insufficient."]
                if self.candidate else
                ["No executable reflected context was established. For DOM XSS, inspect client JavaScript with analyze_dom_xss and test query/hash sources in a browser."]
            ),
        }


def audit_reflected_xss(
    probe: Probe,
    baseline: Baseline,
    *,
    method: str,
    url: str,
    param: str,
    in_body: bool = False,
    identity_headers: dict[str, str] | None = None,
    confirm_state_change: bool = False,
) -> XssAudit:
    """Map reflection contexts and encoding; never claim execution from HTTP alone."""
    method = method.upper()
    if not param:
        raise ValueError("param is required")
    if method not in {"GET", "HEAD"} and not confirm_state_change:
        raise ValueError(
            "confirm_state_change=true is required for non-GET reflection probes; "
            "use only a disposable workflow and clean up any persisted canaries"
        )
    canary = "wx" + uuid.uuid4().hex[:10] + "yz"
    first = _send(probe, method, url, param, canary, in_body, identity_headers)
    observations = [{
        "probe": "alphanumeric_canary",
        "status": first.status,
        "body_sha1": first.body_sha1[:12],
        "content_type": _header(first, "content-type"),
        "blocked_or_error": first.blocked_heuristic or bool(first.error),
    }]
    if baseline.classify(first) == "blocked" or first.error:
        return XssAudit(url, method, param, False, False, "blocked_or_error", observations=observations)
    first_body = first.body_text or first.body_snippet
    if canary not in first_body:
        return XssAudit(url, method, param, False, False, "not_reflected", observations=observations)

    contexts = reflection_contexts(first_body, canary)
    content_type = _header(first, "content-type").lower()
    html_interpreted = "text/html" in content_type or "application/xhtml" in content_type or (
        not content_type and bool(re.search(r"(?i)<(?:html|body|div|script|input|svg)\b", first_body))
    )
    meta_probe = "".join(f"{canary}{index}{char}" for index, char in enumerate(_META_CHARS))
    second = _send(probe, method, url, param, meta_probe, in_body, identity_headers)
    second_body = second.body_text or second.body_snippet
    raw = _raw_meta_characters(second_body, canary)
    observations.append({
        "probe": "context_metacharacters",
        "status": second.status,
        "body_sha1": second.body_sha1[:12],
        "content_type": _header(second, "content-type"),
        "blocked_or_error": second.blocked_heuristic or bool(second.error),
    })
    reasons = []
    if html_interpreted and not second.blocked_heuristic and not second.error:
        for context in contexts:
            possible, reason = _context_candidate(context, raw)
            if possible:
                reasons.append(f"{context['context']}: {reason}")
    candidate = bool(reasons)
    classification = (
        "browser_execution_required" if candidate else
        "non_html_reflection" if not html_interpreted else
        "encoded_or_non_executable_reflection"
    )
    return XssAudit(
        url=url,
        method=method,
        parameter=param,
        reflected=True,
        candidate=candidate,
        classification=classification,
        contexts=contexts,
        raw_meta_characters=raw,
        candidate_reasons=reasons,
        observations=observations,
    )


DOM_SOURCE_PATTERNS = {
    "location": re.compile(r"\b(?:window\.)?location(?:\.(?:href|search|hash|pathname))?\b"),
    "document_url": re.compile(r"\bdocument\.(?:URL|documentURI|baseURI|referrer|cookie)\b"),
    "window_name": re.compile(r"\bwindow\.name\b"),
    "postmessage": re.compile(r"\b(?:addEventListener\s*\(\s*['\"]message|onmessage\s*=)"),
    "web_storage": re.compile(r"\b(?:localStorage|sessionStorage)\b"),
}
DOM_SINK_PATTERNS = {
    "html_sink": re.compile(r"\.(?:innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\(|\bdocument\.(?:write|writeln)\s*\(|\.on[a-z]+\s*="),
    "javascript_execution_sink": re.compile(r"\b(?:eval|Function|setTimeout|setInterval)\s*\("),
    "jquery_html_sink": re.compile(r"(?:\$|jQuery)\s*\(|\.(?:add|after|append|prepend|before|html|insertAfter|insertBefore|replaceAll|replaceWith|wrap|wrapInner|wrapAll)\s*\(|(?:jQuery|\$)\.parseHTML\s*\("),
    "navigation_sink": re.compile(r"\b(?:window\.)?location(?:\.href)?\s*=|\.(?:setAttribute|attr)\s*\(\s*['\"](?:href|src)"),
}


def analyze_dom_javascript(source: str) -> dict[str, Any]:
    """Offline DOM-XSS source/sink inventory. It does not claim taint flow."""
    if len(source) > 2_000_000:
        raise ValueError("JavaScript source is bounded to 2,000,000 characters")
    sources = []
    sinks = []
    lines = source.splitlines()
    for line_number, line in enumerate(lines, 1):
        for name, pattern in DOM_SOURCE_PATTERNS.items():
            if pattern.search(line):
                sources.append({"type": name, "line": line_number})
        for name, pattern in DOM_SINK_PATTERNS.items():
            if pattern.search(line):
                sinks.append({"type": name, "line": line_number})
    return {
        "methodology": DOM_REFERENCE,
        "sources": sources[:1000],
        "sinks": sinks[:1000],
        "source_count": len(sources),
        "sink_count": len(sinks),
        "candidate": bool(sources and sinks),
        "confirmed": False,
        "note": "Source and sink presence does not prove data flow. Use browser execution or manual data-flow review to confirm DOM XSS.",
    }


def _validate_token(token: str | None) -> str:
    value = token or ("xss" + uuid.uuid4().hex[:12])
    if not _TOKEN_RE.fullmatch(value):
        raise ValueError("token must contain 6-64 letters, numbers, underscores, or hyphens")
    return value


def build_xss_payloads(token: str | None = None) -> dict[str, Any]:
    """Generate bounded, non-exfiltrating marker payloads for known contexts."""
    token = _validate_token(token)
    call = f"window.__wafmcpXssHit('{token}'"
    payloads = [
        {
            "name": "html_img_onerror",
            "context": "html_text",
            "payload": f"<img src=x onerror={call},'html_img_onerror')>",
            "interaction_required": False,
        },
        {
            "name": "html_svg_onload",
            "context": "html_text",
            "payload": f"<svg onload={call},'html_svg_onload')>",
            "interaction_required": False,
        },
        {
            "name": "double_attribute_breakout",
            "context": "html_attribute_double",
            "payload": f'\"><img src=x onerror={call},\'double_attribute_breakout\')>',
            "interaction_required": False,
        },
        {
            "name": "single_attribute_breakout",
            "context": "html_attribute_single",
            "payload": f"'><img src=x onerror={call},'single_attribute_breakout')>",
            "interaction_required": False,
        },
        {
            "name": "double_attribute_event",
            "context": "html_attribute_double_without_angle_brackets",
            "payload": f'" autofocus onfocus={call},\'double_attribute_event\') x="',
            "interaction_required": False,
        },
        {
            "name": "single_attribute_event",
            "context": "html_attribute_single_without_angle_brackets",
            "payload": f"' autofocus onfocus={call},'single_attribute_event') x='",
            "interaction_required": False,
        },
        {
            "name": "script_end_breakout",
            "context": "javascript",
            "payload": f"</script><img src=x onerror={call},'script_end_breakout')>",
            "interaction_required": False,
        },
        {
            "name": "javascript_single_string",
            "context": "javascript_single_string",
            "payload": f"';{call},'javascript_single_string');//",
            "interaction_required": False,
        },
        {
            "name": "javascript_double_string",
            "context": "javascript_double_string",
            "payload": f'\";{call},\'javascript_double_string\');//',
            "interaction_required": False,
        },
        {
            "name": "javascript_single_string_backslash",
            "context": "javascript_single_string_with_quote_escaping",
            "payload": f"\\';{call},'javascript_single_string_backslash');//",
            "interaction_required": False,
        },
        {
            "name": "javascript_double_string_backslash",
            "context": "javascript_double_string_with_quote_escaping",
            "payload": f'\\\";{call},\'javascript_double_string_backslash\');//',
            "interaction_required": False,
        },
        {
            "name": "javascript_template_expression",
            "context": "javascript_template_literal",
            "payload": "${" + call + ",'javascript_template_expression')}" ,
            "interaction_required": False,
        },
        {
            "name": "direct_javascript_expression",
            "context": "event_handler_or_javascript_code",
            "payload": call + ",'direct_javascript_expression')",
            "interaction_required": False,
        },
        {
            "name": "javascript_url",
            "context": "url_attribute",
            "payload": "javascript:" + call + ",'javascript_url')",
            "interaction_required": True,
        },
    ]
    return {
        "methodology": METHODOLOGY,
        "token": token,
        "payloads": payloads,
        "safety": "Payloads only call a temporary in-page marker function; they do not access cookies, storage, credentials, or external networks.",
    }


def _injected_url(base_url: str, param: str, payload: str, location: str) -> str:
    parts = urlsplit(base_url)
    if location == "query":
        values = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != param]
        values.append((param, payload))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(values), parts.fragment))
    if location == "fragment":
        values = [(key, value) for key, value in parse_qsl(parts.fragment, keep_blank_values=True) if key != param]
        values.append((param, payload))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, urlencode(values)))
    if location == "path_placeholder":
        if "{XSS}" not in base_url:
            raise ValueError("path_placeholder mode requires the literal {XSS} in url")
        return base_url.replace("{XSS}", quote(payload, safe=""))
    if location == "existing":
        return base_url
    raise ValueError("injection_location must be query, fragment, or path_placeholder")


def _cookie_list(cookie_header: str, url: str) -> list[dict[str, Any]]:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}/"
    cookies = []
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        if name.strip():
            cookies.append({"name": name.strip(), "value": value.strip(), "url": origin})
    return cookies


def _websocket_scope_url(url: str) -> str:
    """Map WebSocket schemes to their HTTP-equivalent default ports for scope checks."""
    parts = urlsplit(url)
    if parts.scheme not in {"ws", "wss"}:
        raise ValueError(f"Unsupported WebSocket URL scheme: {parts.scheme or '(missing)'}")
    scheme = "https" if parts.scheme == "wss" else "http"
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _browser_run(
    scope: Scope,
    *,
    rules: Rules,
    url: str,
    param: str,
    injection_location: str,
    token: str,
    payloads: list[dict[str, Any]],
    identity_headers: dict[str, str] | None,
    trials: int,
    wait_ms: int,
    timeout_ms: int,
    headless: bool,
) -> dict[str, Any]:
    sync_playwright = _ensure_playwright()
    headers = rules.inject_headers(dict(identity_headers or {}))
    headers = sanitize_headers(headers)
    cookie_header = next((value for key, value in headers.items() if key.lower() == "cookie"), "")
    safe_headers = {
        key: value for key, value in headers.items()
        if key.lower() not in {"cookie", "host", "content-length", "connection"}
    }
    observations = []
    blocked_resources: set[str] = set()
    browser_error = None
    winning_payload = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=safe_headers,
                service_workers="block",
            )
            if cookie_header:
                context.add_cookies(_cookie_list(cookie_header, url))
            context.add_init_script(
                f"""(() => {{
                    const token = {json.dumps(token)};
                    window.__wafmcpXssHits = [];
                    window.__wafmcpXssHit = (candidate, vector) => {{
                        if (candidate === token) {{
                            window.__wafmcpXssHits.push({{token: candidate, vector: String(vector || '')}});
                        }}
                    }};
                }})();"""
            )

            def route_request(route, request):
                if request.url.startswith(("data:", "blob:", "about:")):
                    route.continue_()
                    return
                try:
                    scope.check(request.url)
                    rules.enforce("GET", request.url)
                    rules.throttle()
                    route.continue_()
                except Exception:
                    blocked_resources.add(request.url[:500])
                    route.abort()

            context.route("**/*", route_request)

            def route_websocket(websocket_route):
                scope_url = _websocket_scope_url(websocket_route.url)
                try:
                    scope.check(scope_url)
                    rules.enforce("GET", scope_url)
                    rules.throttle()
                    websocket_route.connect_to_server()
                except Exception:
                    blocked_resources.add(websocket_route.url[:500])
                    # A routed WebSocket does not contact its server unless
                    # connect_to_server() is called. Close the local side too.
                    websocket_route.close(code=1008, reason="Blocked by wafmcp scope or rules")

            context.route_web_socket("**/*", route_websocket)
            for payload in payloads:
                trial_rows = []
                for _ in range(trials):
                    target_url = _injected_url(url, param, payload["payload"], injection_location)
                    scope.check(target_url)
                    page = context.new_page()
                    page_errors: list[str] = []
                    page.on("pageerror", lambda error: page_errors.append(str(error)[:300]))
                    response = None
                    hits: list[dict[str, str]] = []
                    error = None
                    csp = ""
                    try:
                        response = page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                        page.wait_for_timeout(wait_ms)
                        interaction_triggered = False
                        if payload.get("interaction_required"):
                            links = page.locator("a[href]")
                            for index in range(min(links.count(), 50)):
                                link = links.nth(index)
                                href = link.get_attribute("href") or ""
                                if href.lower().startswith("javascript:") and token in href:
                                    link.click(timeout=2000)
                                    interaction_triggered = True
                                    page.wait_for_timeout(100)
                                    break
                        hits = page.evaluate("() => window.__wafmcpXssHits || []")
                        if response:
                            csp = response.headers.get("content-security-policy", "")
                    except Exception as exc:
                        error = f"{type(exc).__name__}: {exc}"
                    trial_rows.append({
                        "status": response.status if response else 0,
                        "marker_hits": hits,
                        "page_errors": page_errors[:5],
                        "csp": csp,
                        "safe_interaction_triggered": interaction_triggered if not error else False,
                        "error": error,
                    })
                    page.close()
                stable = all(any(hit.get("token") == token for hit in row["marker_hits"]) for row in trial_rows)
                observations.append({
                    "payload_name": payload["name"],
                    "context": payload["context"],
                    "stable_execution": stable,
                    "trials": trial_rows,
                })
                if stable:
                    winning_payload = payload
                    break
            browser.close()
    except BrowserUnavailable:
        raise
    except Exception as exc:
        browser_error = f"{type(exc).__name__}: {exc}"
    return {
        "executed": winning_payload is not None,
        "winning_payload": winning_payload,
        "observations": observations,
        "blocked_out_of_scope_resources": sorted(blocked_resources)[:100],
        "browser_error": browser_error,
    }


BrowserRunner = Callable[..., dict[str, Any]]


@dataclass
class XssExecutionVerdict:
    confirmed: bool
    xss_type: str
    token: str
    evidence: list[str]
    browser: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "confirmed": self.confirmed,
            "oracle": "browser_javascript_execution",
            "xss_type": self.xss_type,
            "token": self.token,
            "evidence": self.evidence,
            "browser": self.browser,
            "next_steps": (
                ["Document the exact execution context and impact for the affected user role. The marker payload itself performs no data access or exfiltration."]
                if self.confirmed else
                ["No stable marker execution was observed. Review CSP, blocked out-of-scope scripts, client-side errors, and the PortSwigger context before trying a different safe context payload."]
            ),
        }


def verify_xss_execution(
    scope: Scope,
    *,
    rules: Rules | None = None,
    url: str,
    param: str,
    injection_location: str = "query",
    identity_headers: dict[str, str] | None = None,
    trials: int = 2,
    wait_ms: int = 1000,
    timeout_ms: int = 20_000,
    headless: bool = True,
    browser_runner: BrowserRunner | None = None,
) -> XssExecutionVerdict:
    """Confirm reflected or DOM XSS by stable execution of a harmless marker."""
    if not 1 <= trials <= 3:
        raise ValueError("trials must be between 1 and 3")
    if not 100 <= wait_ms <= 10_000:
        raise ValueError("wait_ms must be between 100 and 10000")
    if not 1_000 <= timeout_ms <= 60_000:
        raise ValueError("timeout_ms must be between 1000 and 60000")
    scope.check(url.replace("{XSS}", "probe"))
    rules = rules or Rules()
    rules.enforce("GET", url.replace("{XSS}", "probe"))
    prepared = build_xss_payloads()
    runner = browser_runner or _browser_run
    browser = runner(
        scope,
        rules=rules,
        url=url,
        param=param,
        injection_location=injection_location,
        token=prepared["token"],
        payloads=prepared["payloads"],
        identity_headers=identity_headers,
        trials=trials,
        wait_ms=wait_ms,
        timeout_ms=timeout_ms,
        headless=headless,
    )
    confirmed = bool(browser.get("executed"))
    xss_type = "dom_or_reflected_xss" if injection_location in {"query", "path_placeholder"} else "dom_xss"
    evidence = [
        f"stable browser marker execution: {confirmed}",
        f"winning payload: {(browser.get('winning_payload') or {}).get('name')}",
        f"trials required per payload: {trials}",
    ]
    return XssExecutionVerdict(confirmed, xss_type, prepared["token"], evidence, browser)


def verify_stored_xss_page(
    scope: Scope,
    *,
    rules: Rules | None = None,
    url: str,
    token: str,
    identity_headers: dict[str, str] | None = None,
    trials: int = 2,
    wait_ms: int = 1000,
    timeout_ms: int = 20_000,
    headless: bool = True,
    browser_runner: BrowserRunner | None = None,
) -> XssExecutionVerdict:
    """Verify a previously stored safe marker without creating or deleting data."""
    token = _validate_token(token)
    if not 1 <= trials <= 3:
        raise ValueError("trials must be between 1 and 3")
    scope.check(url)
    rules = rules or Rules()
    rules.enforce("GET", url)
    runner = browser_runner or _browser_run
    browser = runner(
        scope,
        rules=rules,
        url=url,
        param="",
        injection_location="existing",
        token=token,
        payloads=[{"name": "stored_existing_marker", "context": "stored", "payload": ""}],
        identity_headers=identity_headers,
        trials=trials,
        wait_ms=wait_ms,
        timeout_ms=timeout_ms,
        headless=headless,
    )
    confirmed = bool(browser.get("executed"))
    evidence = [
        f"stored marker token: {token}",
        f"stable browser marker execution: {confirmed}",
        "This oracle only viewed the supplied page; payload creation and cleanup remain operator-controlled.",
    ]
    return XssExecutionVerdict(confirmed, "stored_xss", token, evidence, browser)
