"""Evidence-first REST API testing based on PortSwigger Web Security Academy.

Discovery is deliberately read-only. Documentation exposure, supported methods,
content types, and response differences are attack-surface signals rather than
vulnerabilities. The two verification helpers require deterministic oracles;
the mass-assignment oracle also requires explicit opt-in and restores state.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from .http_client import Probe, Response


METHODOLOGY = "https://portswigger.net/web-security/api-testing"
SSPP_METHODOLOGY = (
    "https://portswigger.net/web-security/api-testing/"
    "server-side-parameter-pollution"
)
DEFAULT_DOC_PATHS = (
    "/api",
    "/openapi.json",
    "/swagger.json",
    "/swagger/index.html",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
SENSITIVE_FIELD = re.compile(
    r"(?:admin|role|privilege|permission|verified|is[_-]?staff|is[_-]?superuser|"
    r"balance|credit|price|discount|status|tier|plan|owner|user[_-]?id|account[_-]?id|"
    r"password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_MISSING = object()


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
        and 200 <= response.status < 300
    )


def _header(response: Response, name: str) -> str:
    name = name.lower()
    return next(
        (str(value) for key, value in response.headers.items() if key.lower() == name),
        "",
    )


def _observation(name: str, response: Response) -> dict[str, Any]:
    return {
        "probe": name,
        "method": response.method,
        "url": response.url,
        "status": response.status,
        "content_type": _header(response, "content-type"),
        "allow": _header(response, "allow"),
        "length": response.length,
        "body_sha1": response.body_sha1[:12],
        "blocked_or_error": response.blocked_heuristic or bool(response.error),
    }


def _document_kind(response: Response, parsed: Any) -> str | None:
    if not _successful(response):
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("paths"), dict):
        if isinstance(parsed.get("openapi"), str):
            return "OpenAPI JSON"
        if isinstance(parsed.get("swagger"), str):
            return "Swagger JSON"
    content_type = _header(response, "content-type").lower()
    body = response.body_text[:100_000].lower()
    if "yaml" in content_type and ("openapi:" in body or "swagger:" in body):
        return "OpenAPI/Swagger YAML"
    if any(marker in body for marker in ("swagger-ui", "swagger ui", "redoc", "openapi explorer")):
        return "interactive API documentation"
    return None


@dataclass
class ApiAudit:
    url: str
    endpoint: dict[str, Any] = field(default_factory=dict)
    documentation: list[dict[str, Any]] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)

    def add_signal(self, type_: str, detail: str) -> None:
        if any(item["type"] == type_ and item["detail"] == detail for item in self.signals):
            return
        self.signals.append({"type": type_, "status": "attack_surface", "detail": detail})

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "url": self.url,
            "endpoint": self.endpoint,
            "documentation": self.documentation,
            "signals": self.signals,
            "confirmed_vulnerabilities": [],
            "next_steps": [
                "Documentation, methods, parameters, and content types are mapping signals, not findings.",
                "Use analyze_openapi to review a discovered JSON specification, then test only concrete "
                "authorization or input-handling hypotheses with an appropriate oracle.",
                "Use find_mass_assignment_candidates before the opt-in verify_mass_assignment oracle; "
                "use verify_api_sspp only where the response provides a deterministic resource oracle.",
            ],
        }


def audit_api(
    probe: Probe,
    *,
    url: str,
    identity_headers: dict[str, str] | None = None,
    doc_paths: list[str] | None = None,
) -> ApiAudit:
    """Map one endpoint and a bounded set of same-origin documentation paths."""
    headers = dict(identity_headers or {})
    audit = ApiAudit(url=url)
    endpoint_get = probe.send("GET", url, headers=headers)
    endpoint_options = probe.send("OPTIONS", url, headers=headers)
    audit.endpoint = {
        "get": _observation("endpoint_get", endpoint_get),
        "options": _observation("endpoint_options", endpoint_options),
        "json_response": isinstance(_parse_json(endpoint_get), (dict, list)),
    }
    allow = _header(endpoint_options, "allow")
    if allow and _successful(endpoint_options):
        audit.add_signal("advertised_methods", f"OPTIONS advertised: {allow}")
    if audit.endpoint["json_response"] and _successful(endpoint_get):
        audit.add_signal("json_api_response", "GET returned a successful JSON response.")
    endpoint_parsed = _parse_json(endpoint_get)
    endpoint_doc_kind = _document_kind(endpoint_get, endpoint_parsed)
    if endpoint_doc_kind:
        endpoint_document: dict[str, Any] = {
            "url": url,
            "kind": endpoint_doc_kind,
            "status": endpoint_get.status,
            "content_type": _header(endpoint_get, "content-type"),
            "body_sha1": endpoint_get.body_sha1[:12],
        }
        if isinstance(endpoint_parsed, dict) and endpoint_doc_kind in {"OpenAPI JSON", "Swagger JSON"}:
            summary = summarize_openapi(endpoint_parsed)
            endpoint_document["spec_version"] = summary["spec_version"]
            endpoint_document["operation_count"] = summary["operation_count"]
        audit.documentation.append(endpoint_document)
        audit.add_signal("api_documentation_exposed", f"{endpoint_doc_kind} discovered at {url}")

    split = urlsplit(url)
    origin = f"{split.scheme}://{split.netloc}/"
    paths = list(DEFAULT_DOC_PATHS)
    for path in doc_paths or []:
        if not isinstance(path, str):
            raise ValueError("each documentation path must be a string")
        if path not in paths:
            paths.append(path)
    if len(paths) > 20:
        raise ValueError("doc_paths is bounded to 20 unique paths")

    seen_urls: set[str] = set()
    for path in paths:
        candidate = urljoin(origin, path)
        candidate_split = urlsplit(candidate)
        if (candidate_split.scheme, candidate_split.netloc) != (split.scheme, split.netloc):
            raise ValueError("doc_paths must remain on the endpoint's origin")
        if candidate in seen_urls or candidate == url:
            continue
        seen_urls.add(candidate)
        response = probe.send("GET", candidate, headers=headers)
        parsed = _parse_json(response)
        kind = _document_kind(response, parsed)
        if not kind:
            continue
        item: dict[str, Any] = {
            "url": candidate,
            "kind": kind,
            "status": response.status,
            "content_type": _header(response, "content-type"),
            "body_sha1": response.body_sha1[:12],
        }
        if isinstance(parsed, dict) and kind in {"OpenAPI JSON", "Swagger JSON"}:
            summary = summarize_openapi(parsed)
            item["spec_version"] = summary["spec_version"]
            item["operation_count"] = summary["operation_count"]
        audit.documentation.append(item)
        audit.add_signal("api_documentation_exposed", f"{kind} discovered at {candidate}")
    return audit


def summarize_openapi(document: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, secret-free summary of an OpenAPI/Swagger JSON document."""
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("document must be an OpenAPI/Swagger JSON object with a paths object")
    spec_version = document.get("openapi") or document.get("swagger") or "unknown"
    servers: list[str] = []
    for item in document.get("servers") or []:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            servers.append(item["url"])
    if not servers and isinstance(document.get("host"), str):
        schemes = document.get("schemes") or ["https"]
        base_path = document.get("basePath") or ""
        servers = [f"{scheme}://{document['host']}{base_path}" for scheme in schemes[:5]]

    components = document.get("components")
    if not isinstance(components, dict):
        components = {}
    schemes_obj = components.get("securitySchemes")
    if not isinstance(schemes_obj, dict):
        legacy_schemes = document.get("securityDefinitions")
        schemes_obj = legacy_schemes if isinstance(legacy_schemes, dict) else {}
    security_schemes = [
        {"name": str(name), "type": str(value.get("type", "")), "scheme": str(value.get("scheme", ""))}
        for name, value in schemes_obj.items()
        if isinstance(value, dict)
    ][:100]

    operations: list[dict[str, Any]] = []
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        path_parameters = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = list(path_parameters)
            if isinstance(operation.get("parameters"), list):
                parameters.extend(operation["parameters"])
            parameter_summary = [
                {"name": str(item.get("name", "")), "in": str(item.get("in", "")), "required": bool(item.get("required"))}
                for item in parameters
                if isinstance(item, dict)
            ][:100]
            content_types: list[str] = []
            request_body = operation.get("requestBody")
            if isinstance(request_body, dict) and isinstance(request_body.get("content"), dict):
                content_types.extend(str(key) for key in request_body["content"])
            consumes = operation.get("consumes") or document.get("consumes") or []
            content_types.extend(str(item) for item in consumes if isinstance(item, str))
            operations.append({
                "path": path,
                "method": method.upper(),
                "operation_id": operation.get("operationId"),
                "deprecated": bool(operation.get("deprecated")),
                "parameters": parameter_summary,
                "request_content_types": sorted(set(content_types)),
                "security": operation.get("security", document.get("security", [])),
            })
            if len(operations) >= 500:
                break
        if len(operations) >= 500:
            break

    schemas = components.get("schemas")
    if not isinstance(schemas, dict):
        legacy_schemas = document.get("definitions")
        schemas = legacy_schemas if isinstance(legacy_schemas, dict) else {}
    sensitive: list[str] = []

    def walk_properties(value: Any, prefix: str, depth: int = 0) -> None:
        if depth > 8 or len(sensitive) >= 200 or not isinstance(value, dict):
            return
        properties = value.get("properties")
        if isinstance(properties, dict):
            for name, schema in properties.items():
                dotted = f"{prefix}.{name}" if prefix else str(name)
                if SENSITIVE_FIELD.search(str(name)):
                    sensitive.append(dotted)
                walk_properties(schema, dotted, depth + 1)
        items = value.get("items")
        if isinstance(items, dict):
            walk_properties(items, f"{prefix}[]", depth + 1)

    for schema_name, schema in list(schemas.items())[:500]:
        walk_properties(schema, str(schema_name))

    return {
        "methodology": METHODOLOGY,
        "spec_version": str(spec_version),
        "title": str(document["info"].get("title", ""))
        if isinstance(document.get("info"), dict) else "",
        "servers": servers[:50],
        "security_schemes": security_schemes,
        "operation_count": len(operations),
        "operations_truncated": len(operations) == 500,
        "operations": operations,
        "review_sensitive_schema_fields": sorted(set(sensitive)),
        "confirmed_vulnerabilities": [],
        "note": "An exposed specification or sensitive field name is not proof of unauthorized access.",
    }


def _flatten(value: Any, prefix: str = "", depth: int = 0) -> dict[str, Any]:
    if depth > 12:
        return {prefix: value}
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(child, path, depth + 1))
        return result
    return {prefix: value}


def mass_assignment_candidates(read_object: dict[str, Any], update_object: dict[str, Any]) -> dict[str, Any]:
    """Compare a read object with an intended update body without contacting a target."""
    if not isinstance(read_object, dict) or not isinstance(update_object, dict):
        raise ValueError("read_object and update_object must be JSON objects")
    read_fields = _flatten(read_object)
    update_fields = _flatten(update_object)
    candidate_names = sorted(path for path in read_fields if path and path not in update_fields)
    candidates = [
        {
            "field": path,
            "value_type": type(read_fields[path]).__name__,
            "sensitive_name": bool(SENSITIVE_FIELD.search(path.split(".")[-1])),
        }
        for path in candidate_names
    ]
    return {
        "methodology": METHODOLOGY,
        "candidates": candidates,
        "sensitive_candidates": [item for item in candidates if item["sensitive_name"]],
        "confirmed_vulnerabilities": [],
        "note": "These are fields returned by a read response but absent from the intended update body. "
        "They are hypotheses only until a reversible state-change oracle proves the server accepts one.",
    }


def _signature(response: Response) -> tuple[int, str]:
    return response.status, response.body_sha1


def _stable(responses: list[Response]) -> bool:
    return bool(responses) and len({_signature(item) for item in responses}) == 1


@dataclass
class ApiSsppVerdict:
    confirmed: bool
    candidate: bool
    confidence: str
    evidence: list[str]
    observations: dict[str, list[dict[str, Any]]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": SSPP_METHODOLOGY,
            "confirmed": self.confirmed,
            "candidate": self.candidate,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "observations": self.observations,
            "next_steps": (
                ["Manually confirm that the injected duplicate parameter changes the backend API request, not a cache/WAF/frontend parser."]
                if self.confirmed else
                ["A response difference alone is not SSPP. Identify a valid backend parameter/value and rerun with a deterministic direct-override control."]
            ),
        }


def verify_api_sspp(
    probe: Probe,
    *,
    url: str,
    parameter: str,
    baseline_value: str,
    override_value: str,
    identity_headers: dict[str, str] | None = None,
    trials: int = 2,
) -> ApiSsppVerdict:
    """Verify query-string SSPP using read-only duplicate-parameter controls."""
    if not parameter or any(char in parameter for char in "&#="):
        raise ValueError("parameter must be a plain query parameter name")
    if baseline_value == override_value:
        raise ValueError("baseline_value and override_value must differ")
    if not 2 <= trials <= 5:
        raise ValueError("trials must be between 2 and 5")
    headers = dict(identity_headers or {})
    values = {
        "baseline": baseline_value,
        "direct_override": override_value,
        "injected_duplicate": f"{baseline_value}&{parameter}={override_value}",
        "truncation": f"{baseline_value}#wafmcp",
        "invalid_parameter": f"{baseline_value}&wafmcp_invalid=x",
    }
    responses: dict[str, list[Response]] = {name: [] for name in values}
    for _ in range(trials):
        for name, value in values.items():
            responses[name].append(
                probe.send("GET", url, headers=headers, params={parameter: value})
            )

    stable = {name: _stable(items) for name, items in responses.items()}
    first = {name: items[0] for name, items in responses.items()}
    all_clean = all(
        stable[name] and _successful(first[name])
        for name in ("baseline", "direct_override", "injected_duplicate")
    )
    override_match = _signature(first["injected_duplicate"]) == _signature(first["direct_override"])
    differs_baseline = _signature(first["injected_duplicate"]) != _signature(first["baseline"])
    confirmed = bool(all_clean and override_match and differs_baseline)
    difference_signal = any(
        stable[name] and _signature(first[name]) != _signature(first["baseline"])
        for name in ("truncation", "invalid_parameter", "injected_duplicate")
    )
    evidence = [
        f"{name}: stable={stable[name]}, status={first[name].status}, body_sha1={first[name].body_sha1[:12]}, "
        f"blocked_or_error={first[name].blocked_heuristic or bool(first[name].error)}"
        for name in values
    ]
    if confirmed:
        evidence.append(
            "Injected encoded duplicate parameter matched the direct override control across trials and differed from baseline."
        )
    elif difference_signal:
        evidence.append("One or more injection-shaped inputs changed the response, but no deterministic override oracle was proven.")
    else:
        evidence.append("No stable parameter-injection effect was observed.")
    observations = {
        name: [_observation(name, item) for item in items]
        for name, items in responses.items()
    }
    return ApiSsppVerdict(
        confirmed=confirmed,
        candidate=bool(difference_signal and not confirmed),
        confidence="high" if confirmed else ("low" if difference_signal else "none"),
        evidence=evidence,
        observations=observations,
    )


def _path_get(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _path_set(value: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    if not parts or any(not part for part in parts):
        raise ValueError("candidate_field must be a dotted JSON object path")
    current = value
    for part in parts[:-1]:
        child = current.get(part)
        if child is None:
            child = {}
            current[part] = child
        if not isinstance(child, dict):
            raise ValueError(f"candidate_field crosses non-object value at {part!r}")
        current = child
    current[parts[-1]] = replacement


@dataclass
class MassAssignmentVerdict:
    confirmed: bool
    changed: bool
    restored: bool
    field: str
    evidence: list[str]
    observations: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "confirmed": self.confirmed,
            "changed": self.changed,
            "restored": self.restored,
            "field": self.field,
            "evidence": self.evidence,
            "observations": self.observations,
            "next_steps": (
                ["Reproduce once manually with the exact update/read pair and document the authorization impact."]
                if self.confirmed else
                (["URGENT: automatic restoration was not verified. Check and restore the resource manually."] if self.changed and not self.restored else
                 ["The candidate field was not proven writable; do not report mass assignment from a response difference alone."])
            ),
        }


def verify_mass_assignment(
    probe: Probe,
    *,
    update_url: str,
    read_url: str,
    method: str,
    base_object: dict[str, Any],
    candidate_field: str,
    test_value: Any,
    identity_headers: dict[str, str] | None = None,
    confirm_state_change: bool = False,
) -> MassAssignmentVerdict:
    """Prove a candidate field is writable, then restore its observed original value."""
    if not confirm_state_change:
        raise ValueError("confirm_state_change=true is required before any state-changing request")
    method = method.upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise ValueError("method must be POST, PUT, or PATCH; DELETE is never allowed")
    if not isinstance(base_object, dict):
        raise ValueError("base_object must be a JSON object")
    headers = dict(identity_headers or {})
    baseline_response = probe.send("GET", read_url, headers=headers)
    baseline_object = _parse_json(baseline_response)
    if not _successful(baseline_response) or not isinstance(baseline_object, dict):
        raise ValueError("read_url must return a successful JSON object before mutation")
    original_value = _path_get(baseline_object, candidate_field)
    if original_value is _MISSING:
        raise ValueError("candidate_field was not present in the baseline read response")
    if original_value == test_value:
        raise ValueError("test_value must differ from the observed original value")

    test_body = copy.deepcopy(base_object)
    restore_body = copy.deepcopy(base_object)
    _path_set(test_body, candidate_field, test_value)
    _path_set(restore_body, candidate_field, original_value)
    observations: dict[str, Any] = {"baseline_read": _observation("baseline_read", baseline_response)}
    evidence = [f"Observed baseline field {candidate_field!r} with type {type(original_value).__name__}."]
    changed = False
    restored = False
    mutation_completed = False
    test_response: Response | None = None
    verify_response: Response | None = None
    restore_response: Response | None = None
    restore_read: Response | None = None
    try:
        test_response = probe.send(method, update_url, headers=headers, json=test_body)
        mutation_completed = True
        verify_response = probe.send("GET", read_url, headers=headers)
        verify_object = _parse_json(verify_response)
        changed = bool(
            _successful(test_response)
            and _successful(verify_response)
            and isinstance(verify_object, dict)
            and _path_get(verify_object, candidate_field) == test_value
        )
    finally:
        if mutation_completed:
            restore_response = probe.send(method, update_url, headers=headers, json=restore_body)
            restore_read = probe.send("GET", read_url, headers=headers)
            restored_object = _parse_json(restore_read)
            restored = bool(
                _successful(restore_response)
                and _successful(restore_read)
                and isinstance(restored_object, dict)
                and _path_get(restored_object, candidate_field) == original_value
            )

    if test_response:
        observations["test_update"] = _observation("test_update", test_response)
    if verify_response:
        observations["test_read"] = _observation("test_read", verify_response)
    if restore_response:
        observations["restore_update"] = _observation("restore_update", restore_response)
    if restore_read:
        observations["restore_read"] = _observation("restore_read", restore_read)
    if changed:
        evidence.append("The candidate field changed to the supplied test value in a fresh GET response.")
    else:
        evidence.append("A fresh GET response did not prove that the candidate field changed.")
    evidence.append(
        "The original value was restored and verified with a fresh GET response."
        if restored else
        "Automatic restoration was not verified; inspect the resource manually."
    )
    return MassAssignmentVerdict(
        confirmed=bool(changed and restored),
        changed=changed,
        restored=restored,
        field=candidate_field,
        evidence=evidence,
        observations=observations,
    )
