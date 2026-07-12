"""Evidence-first GraphQL probes based on PortSwigger Web Security Academy.

All discovery probes are read-only queries. Mutation execution is deliberately
out of scope for this module: accepting GET, form-encoded requests, aliases, or
batching is an attack *surface*, not a confirmed vulnerability. A separate
access-control oracle compares the same read-only query as owner, attacker, and
anonymous identities to prove GraphQL IDOR/BOLA without changing server state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .http_client import Probe, Response


METHODOLOGY = "https://portswigger.net/web-security/graphql"
UNIVERSAL_QUERY = "query{__typename}"
INTROSPECTION_PROBE = "query{__schema{queryType{name} mutationType{name}}}"
INTROSPECTION_BYPASS = "query{__schema\n{queryType{name} mutationType{name}}}"
SUGGESTION_PROBE = "query{__typenam}"
ALIAS_PROBE = "query WafmcpAliasProbe{a:__typename b:__typename}"
SCHEMA_QUERY = """query WafmcpSchema {
  __schema {
    queryType { name fields { name args { name } } }
    mutationType { name fields { name args { name } } }
    subscriptionType { name fields { name args { name } } }
    types { kind name }
  }
}"""


def _parse_json(response: Response) -> Any:
    if response.error or not response.body_text:
        return None
    try:
        return json.loads(response.body_text)
    except (TypeError, ValueError):
        return None


def _successful(response: Response) -> bool:
    return bool(
        not response.error
        and not response.blocked_heuristic
        and response.status in {200, 201, 202, 203, 206}
    )


def _error_messages(parsed: Any) -> list[str]:
    if not isinstance(parsed, dict) or not isinstance(parsed.get("errors"), list):
        return []
    messages: list[str] = []
    for item in parsed["errors"][:5]:
        if isinstance(item, dict) and isinstance(item.get("message"), str):
            messages.append(item["message"][:300])
    return messages


def _typename(parsed: Any, key: str = "__typename") -> str | None:
    if not isinstance(parsed, dict) or not isinstance(parsed.get("data"), dict):
        return None
    value = parsed["data"].get(key)
    return value if isinstance(value, str) else None


def _introspection(parsed: Any) -> dict[str, Any] | None:
    if not isinstance(parsed, dict) or not isinstance(parsed.get("data"), dict):
        return None
    schema = parsed["data"].get("__schema")
    if not isinstance(schema, dict):
        return None
    query_type = schema.get("queryType")
    if not isinstance(query_type, dict) or not isinstance(query_type.get("name"), str):
        return None
    return schema


def _observation(name: str, response: Response, parsed: Any) -> dict[str, Any]:
    return {
        "probe": name,
        "method": response.method,
        "status": response.status,
        "content_type": next(
            (str(value) for key, value in response.headers.items()
             if key.lower() == "content-type"),
            "",
        ),
        "blocked_or_error": response.blocked_heuristic or bool(response.error),
        "graphql_data": isinstance(parsed, dict) and "data" in parsed,
        "error_messages": _error_messages(parsed),
        "body_sha1": response.body_sha1[:12],
    }


def _schema_summary(parsed: Any) -> dict[str, Any]:
    schema = _introspection(parsed)
    if not schema:
        return {}

    def operation(name: str) -> dict[str, Any] | None:
        value = schema.get(name)
        if not isinstance(value, dict):
            return None
        fields = value.get("fields")
        field_names = [
            item["name"] for item in fields or []
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
        return {"name": value.get("name"), "fields": field_names}

    types = schema.get("types")
    type_names = [
        item["name"] for item in types or []
        if isinstance(item, dict) and isinstance(item.get("name"), str)
        and not item["name"].startswith("__")
    ]
    result = {
        "query": operation("queryType"),
        "mutation": operation("mutationType"),
        "subscription": operation("subscriptionType"),
        "type_count": len(type_names),
        "type_names": type_names[:200],
    }
    sensitive = re.compile(
        r"(?:password|passwd|secret|token|api.?key|email|user.?id|ssn|credit|admin)",
        re.IGNORECASE,
    )
    exposed_names: list[str] = []
    for section in (result["query"], result["mutation"], result["subscription"]):
        if isinstance(section, dict):
            exposed_names.extend(name for name in section["fields"] if sensitive.search(name))
    result["review_sensitive_field_names"] = sorted(set(exposed_names))
    return result


@dataclass
class GraphQLAudit:
    url: str
    endpoint_confirmed: bool = False
    confirmed_transports: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    schema: dict[str, Any] = field(default_factory=dict)

    def add_signal(self, type_: str, severity: str, status: str, detail: str) -> None:
        if any(item["type"] == type_ for item in self.signals):
            return
        self.signals.append({
            "type": type_,
            "severity": severity,
            "status": status,
            "detail": detail,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "url": self.url,
            "endpoint_confirmed": self.endpoint_confirmed,
            "confirmed_transports": self.confirmed_transports,
            "observations": self.observations,
            "signals": self.signals,
            "schema": self.schema,
            "confirmed_vulnerabilities": [],
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        if not self.endpoint_confirmed:
            return [
                "No GraphQL endpoint was confirmed at this URL. Try PortSwigger's common "
                "paths (/graphql, /api, /api/graphql, /graphql/api, /graphql/graphql, and /v1 variants)."
            ]
        steps = [
            "Endpoint confirmation is not a vulnerability. Review captured application queries "
            "and schema fields for object-level authorization and argument injection."
        ]
        signal_types = {item["type"] for item in self.signals}
        if "introspection_enabled" in signal_types or "introspection_filter_bypass" in signal_types:
            steps.append(
                "Review the schema for unintended private fields and operations. Introspection "
                "alone may be intentional for a public API; prove exposed sensitive capability."
            )
        if "graphql_suggestions_enabled" in signal_types:
            steps.append(
                "Suggestions disclose schema names but are not a standalone high-impact finding; "
                "use them only to guide authorized manual testing."
            )
        if "csrf_transport_precondition" in signal_types:
            steps.append(
                "GET/form acceptance is only a CSRF precondition. Confirm with a real victim "
                "browser, ambient cookies, absent CSRF defenses, and an authorized reversible mutation."
            )
        if "batching_accepted" in signal_types or "aliases_accepted" in signal_types:
            steps.append(
                "Batching/aliases are normal GraphQL features. Test rate-limit accounting within "
                "program limits and report only a demonstrated control bypass."
            )
        return steps


def audit_graphql(
    probe: Probe,
    *,
    url: str,
    identity_headers: dict[str, str] | None = None,
    include_schema: bool = False,
    test_get: bool = True,
    test_form: bool = True,
    test_batching: bool = True,
    test_aliases: bool = True,
    test_suggestions: bool = True,
    test_introspection_bypass: bool = True,
) -> GraphQLAudit:
    """Run bounded, read-only GraphQL discovery and configuration probes."""
    headers = dict(identity_headers or {})
    audit = GraphQLAudit(url=url)

    def send_json(name: str, query: str | list[dict[str, str]]) -> tuple[Response, Any]:
        body: Any = query if isinstance(query, list) else {"query": query}
        response = probe.send("POST", url, headers=headers, json=body)
        parsed = _parse_json(response)
        audit.observations.append(_observation(name, response, parsed))
        return response, parsed

    def send_get(name: str, query: str) -> tuple[Response, Any]:
        response = probe.send("GET", url, headers=headers, params={"query": query})
        parsed = _parse_json(response)
        audit.observations.append(_observation(name, response, parsed))
        return response, parsed

    def send_form(name: str, query: str) -> tuple[Response, Any]:
        response = probe.send("POST", url, headers=headers, data={"query": query})
        parsed = _parse_json(response)
        audit.observations.append(_observation(name, response, parsed))
        return response, parsed

    transports: dict[str, Callable[[str, str], tuple[Response, Any]]] = {
        "post_json": lambda name, query: send_json(name, query),
    }
    post_response, post_universal = send_json("universal_post_json", UNIVERSAL_QUERY)
    if _successful(post_response) and _typename(post_universal):
        audit.confirmed_transports.append("POST application/json")

    get_universal = None
    if test_get:
        transports["get"] = send_get
        get_response, get_universal = send_get("universal_get", UNIVERSAL_QUERY)
        if _successful(get_response) and _typename(get_universal):
            audit.confirmed_transports.append("GET query parameter")

    form_universal = None
    if test_form:
        transports["post_form"] = send_form
        form_response, form_universal = send_form("universal_post_form", UNIVERSAL_QUERY)
        if _successful(form_response) and _typename(form_universal):
            audit.confirmed_transports.append("POST application/x-www-form-urlencoded")

    audit.endpoint_confirmed = bool(audit.confirmed_transports)
    simple_transports = [
        item for item in audit.confirmed_transports
        if item.startswith("GET") or "x-www-form-urlencoded" in item
    ]
    if simple_transports:
        audit.add_signal(
            "csrf_transport_precondition", "medium", "candidate",
            "Endpoint accepts browser-simple GraphQL transport(s): "
            + ", ".join(simple_transports)
            + ". A state-changing mutation, ambient auth, and absent CSRF defenses are still required.",
        )
    if not audit.endpoint_confirmed:
        return audit

    introspection_transport: str | None = None
    intro_response, intro = send_json("introspection_post_json", INTROSPECTION_PROBE)
    intro_schema = _introspection(intro) if _successful(intro_response) else None
    if intro_schema:
        introspection_transport = "post_json"
        audit.add_signal(
            "introspection_enabled", "info", "exposure",
            "Standard __schema introspection returned query type information. Review whether this is intended.",
        )
    elif test_introspection_bypass:
        for transport_name, sender in transports.items():
            bypass_response, bypass = sender(
                f"introspection_bypass_{transport_name}", INTROSPECTION_BYPASS
            )
            if _successful(bypass_response) and _introspection(bypass):
                introspection_transport = transport_name
                audit.add_signal(
                    "introspection_filter_bypass", "medium", "candidate",
                    f"Standard introspection failed but the whitespace/newline variant worked over {transport_name}.",
                )
                intro = bypass
                intro_schema = _introspection(bypass)
                break

    if intro_schema and isinstance(intro_schema.get("mutationType"), dict) and simple_transports:
        audit.add_signal(
            "csrf_mutation_surface", "medium", "candidate",
            "Schema has a mutation root and simple browser transports are accepted. No mutation was executed; CSRF is unconfirmed.",
        )

    if test_suggestions:
        suggestion_response, suggestion = send_json("suggestion_probe", SUGGESTION_PROBE)
        messages = _error_messages(suggestion)
        if (
            not suggestion_response.error
            and not suggestion_response.blocked_heuristic
            and suggestion_response.status in {200, 400, 422}
            and any("did you mean" in message.lower() for message in messages)
        ):
            audit.add_signal(
                "graphql_suggestions_enabled", "info", "exposure",
                "Invalid-field errors include schema suggestions. This can assist schema recovery when introspection is disabled.",
            )

    if test_aliases:
        alias_response, alias = send_json("alias_probe", ALIAS_PROBE)
        if _successful(alias_response) and _typename(alias, "a") and _typename(alias, "b"):
            audit.add_signal(
                "aliases_accepted", "info", "attack_surface",
                "Multiple aliased root fields execute in one HTTP request. This is normal unless rate-limit accounting can be bypassed.",
            )

    if test_batching:
        batch_response, batch = send_json(
            "batch_probe",
            [{"query": UNIVERSAL_QUERY}, {"query": UNIVERSAL_QUERY}],
        )
        if (
            _successful(batch_response)
            and isinstance(batch, list)
            and len(batch) == 2
            and all(_typename(item) for item in batch)
        ):
            audit.add_signal(
                "batching_accepted", "info", "attack_surface",
                "JSON query batching executes multiple operations per HTTP request. This is not a finding without a demonstrated control bypass.",
            )

    if include_schema and introspection_transport:
        sender = transports[introspection_transport]
        schema_http_response, schema_response = sender("bounded_schema", SCHEMA_QUERY)
        audit.schema = _schema_summary(schema_response) if _successful(schema_http_response) else {}
        if audit.schema.get("review_sensitive_field_names"):
            audit.add_signal(
                "sensitive_field_names", "info", "review",
                "Schema field names match potentially sensitive concepts. Names alone do not prove unauthorized data exposure.",
            )

    return audit


@dataclass
class GraphQLAccessVerdict:
    confirmed: bool
    confidence: float
    evidence: list[str]
    trials: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "confirmed": self.confirmed,
            "oracle": "graphql_access_control",
            "confidence": round(self.confidence, 2),
            "trials": self.trials,
            "evidence": self.evidence,
        }


def _data_signature(response: Response) -> tuple[int, str] | None:
    parsed = _parse_json(response)
    if response.status not in {200, 201, 202, 203, 206} or not isinstance(parsed, dict):
        return None
    if parsed.get("errors") or "data" not in parsed or parsed["data"] is None:
        return None
    normalized = json.dumps(parsed["data"], sort_keys=True, separators=(",", ":"))
    return response.status, hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_graphql_access(
    probe: Probe,
    *,
    url: str,
    query: str,
    variables: dict[str, Any] | None,
    owner_headers: dict[str, str],
    attacker_headers: dict[str, str],
    operation_name: str | None = None,
    trials: int = 2,
) -> GraphQLAccessVerdict:
    """Confirm GraphQL IDOR/BOLA using the same read-only query as 3 principals."""
    without_comments = re.sub(r"#[^\n]*", "", query)
    if re.search(r"\b(?:mutation|subscription)\b", without_comments, re.IGNORECASE):
        raise ValueError("verify_graphql_access accepts read-only query operations only")
    if not owner_headers or not attacker_headers:
        raise ValueError("owner and attacker identities must both be authenticated")

    payload: dict[str, Any] = {"query": query, "variables": variables or {}}
    if operation_name:
        payload["operationName"] = operation_name

    owner_sigs: list[tuple[int, str] | None] = []
    attacker_sigs: list[tuple[int, str] | None] = []
    anon_sigs: list[tuple[int, str] | None] = []
    evidence: list[str] = []

    for _ in range(max(1, min(trials, 5))):
        owner = probe.send("POST", url, headers=owner_headers, json=payload)
        attacker = probe.send("POST", url, headers=attacker_headers, json=payload)
        anonymous = probe.send("POST", url, headers={}, json=payload)
        if owner.blocked_heuristic or attacker.blocked_heuristic:
            evidence.append("trial skipped: owner or attacker response was blocked/WAF-shaped")
            continue
        owner_sigs.append(_data_signature(owner))
        attacker_sigs.append(_data_signature(attacker))
        anon_sigs.append(_data_signature(anonymous))

    evidence.append(f"owner data signatures: {[(s[0], s[1][:12]) if s else None for s in owner_sigs]}")
    evidence.append(f"attacker signatures: {[(s[0], s[1][:12]) if s else None for s in attacker_sigs]}")
    evidence.append(f"anonymous control: {[(s[0], s[1][:12]) if s else None for s in anon_sigs]}")
    if not owner_sigs or any(sig is None for sig in owner_sigs):
        return GraphQLAccessVerdict(
            False, 0.0, evidence + ["owner query did not return stable readable GraphQL data"],
            len(owner_sigs),
        )

    stable_owner = len(set(owner_sigs)) == 1
    owner_signature = owner_sigs[0]
    attacker_reads_owner = all(sig == owner_signature for sig in attacker_sigs)
    anonymous_denied = all(sig != owner_signature for sig in anon_sigs)
    confirmed = bool(
        stable_owner
        and attacker_sigs
        and len(attacker_sigs) == len(owner_sigs)
        and attacker_reads_owner
        and anonymous_denied
    )
    if attacker_reads_owner and not anonymous_denied:
        evidence.append("anonymous receives the same data; resource appears public, not IDOR")
    elif confirmed:
        evidence.append(
            "different authenticated identity received the owner's exact GraphQL data while anonymous was denied"
        )
    return GraphQLAccessVerdict(
        confirmed,
        0.97 if confirmed else 0.1,
        evidence,
        len(owner_sigs),
    )
