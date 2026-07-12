"""Evidence-first business-logic testing based on PortSwigger Academy.

Logic flaws are domain-specific, so this module does not pretend that generic
response anomalies are vulnerabilities. It provides an offline assumption map,
a read-only workflow-gate oracle, and an explicit reversible state-invariant
oracle. Confirmation always depends on an operator-defined business rule.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any

from .http_client import Probe, Response


METHODOLOGY = "https://portswigger.net/web-security/logic-flaws"
EXAMPLES = "https://portswigger.net/web-security/logic-flaws/examples"
MUTATING_METHODS = {"POST", "PUT", "PATCH"}
OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "not_exists"}
SENSITIVE_NAMES = re.compile(
    r"(?:price|cost|total|amount|balance|credit|discount|coupon|quantity|stock|"
    r"role|admin|privilege|permission|verified|status|tier|plan|owner|user.?id|"
    r"account.?id|currency|limit|commission|fee)",
    re.IGNORECASE,
)
_MISSING = object()
_VOLATILE = object()


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


def _observation(name: str, response: Response, assertion_result: bool | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "probe": name,
        "method": response.method,
        "url": response.url,
        "status": response.status,
        "length": response.length,
        "body_sha1": response.body_sha1[:12],
        "blocked_or_error": response.blocked_heuristic or bool(response.error),
    }
    if assertion_result is not None:
        result["assertion_satisfied"] = assertion_result
    return result


def _path_get(value: Any, path: str) -> Any:
    if not isinstance(path, str) or not path:
        raise ValueError("assertion/invariant path must be a non-empty dotted JSON path")
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _ignore_path(value: Any, path: str) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return
    leaf = parts[-1]
    if isinstance(current, dict) and leaf in current:
        current[leaf] = _VOLATILE
    elif isinstance(current, list) and leaf.isdigit() and int(leaf) < len(current):
        current[int(leaf)] = _VOLATILE


def _normalized_state(value: Any, volatile_paths: list[str]) -> Any:
    normalized = copy.deepcopy(value)
    for path in volatile_paths:
        _ignore_path(normalized, path)
    return normalized


def _validate_assertion(assertion: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(assertion, dict):
        raise ValueError("assertion must be a JSON object")
    path = assertion.get("path")
    operator = assertion.get("operator")
    if not isinstance(path, str) or not path:
        raise ValueError("assertion.path must be a non-empty string")
    if operator not in OPERATORS:
        raise ValueError(f"assertion.operator must be one of {sorted(OPERATORS)}")
    if operator not in {"exists", "not_exists"} and "value" not in assertion:
        raise ValueError(f"assertion.value is required for operator {operator!r}")
    if operator in {"in", "not_in"} and not isinstance(assertion.get("value"), list):
        raise ValueError(f"assertion.value must be an array for operator {operator!r}")
    return assertion


def _evaluate(document: Any, assertion: dict[str, Any]) -> tuple[bool, Any]:
    assertion = _validate_assertion(assertion)
    actual = _path_get(document, assertion["path"])
    operator = assertion["operator"]
    if operator == "exists":
        return actual is not _MISSING, actual
    if operator == "not_exists":
        return actual is _MISSING, actual
    if actual is _MISSING:
        return False, actual
    expected = assertion["value"]
    try:
        if operator == "eq":
            return actual == expected, actual
        if operator == "ne":
            return actual != expected, actual
        if operator == "gt":
            return actual > expected, actual
        if operator == "gte":
            return actual >= expected, actual
        if operator == "lt":
            return actual < expected, actual
        if operator == "lte":
            return actual <= expected, actual
        if operator == "in":
            return actual in expected, actual
        if operator == "not_in":
            return actual not in expected, actual
    except (TypeError, ValueError):
        return False, actual
    raise ValueError(f"unsupported assertion operator {operator!r}")


def _assertion_label(assertion: dict[str, Any]) -> str:
    if assertion["operator"] in {"exists", "not_exists"}:
        return f"{assertion['path']} {assertion['operator']}"
    return f"{assertion['path']} {assertion['operator']} {assertion.get('value')!r}"


def build_logic_test_plan(workflow: dict[str, Any]) -> dict[str, Any]:
    """Create a bounded offline test plan from explicit domain assumptions."""
    if not isinstance(workflow, dict):
        raise ValueError("workflow must be a JSON object")
    steps = workflow.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("workflow.steps must be a non-empty array")
    if len(steps) > 50:
        raise ValueError("workflow.steps is bounded to 50 entries")
    invariants = workflow.get("invariants") or []
    if not isinstance(invariants, list) or len(invariants) > 50:
        raise ValueError("workflow.invariants must be an array with at most 50 entries")
    for invariant in invariants:
        _validate_assertion(invariant)

    parameter_tests: list[dict[str, Any]] = []
    sequence_tests: list[dict[str, Any]] = []
    client_trust_tests: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError("each workflow step must be a JSON object")
        name = str(step.get("name") or f"step_{index + 1}")
        if name in seen_names:
            raise ValueError(f"duplicate workflow step name {name!r}")
        seen_names.add(name)
        method = str(step.get("method") or "GET").upper()
        parameters = step.get("parameters") or []
        if not isinstance(parameters, list) or len(parameters) > 100:
            raise ValueError(f"parameters for {name!r} must be an array with at most 100 entries")
        prerequisites = step.get("prerequisites") or []
        if not isinstance(prerequisites, list):
            raise ValueError(f"prerequisites for {name!r} must be an array")
        for prerequisite in prerequisites:
            sequence_tests.append({
                "step": name,
                "test": "skip_prerequisite",
                "prerequisite": str(prerequisite),
                "expected": "server rejects the step or withholds the protected outcome",
            })
        if method in MUTATING_METHODS:
            sequence_tests.append({
                "step": name,
                "test": "repeat_step",
                "expected": "replay does not duplicate a single-use effect",
            })
        if index > 0:
            sequence_tests.append({
                "step": name,
                "test": "out_of_order_access",
                "expected": "server verifies current workflow state rather than trusting navigation order",
            })

        for parameter in parameters:
            if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
                raise ValueError(f"each parameter for {name!r} needs a string name")
            param_name = parameter["name"]
            param_type = str(parameter.get("type") or "string").lower()
            if parameter.get("required"):
                parameter_tests.extend([
                    {"step": name, "parameter": param_name, "test": "omit_name", "expected": "rejected server-side"},
                    {"step": name, "parameter": param_name, "test": "empty_value", "expected": "rejected or safely defaulted"},
                    {"step": name, "parameter": param_name, "test": "null_value", "expected": "rejected or safely defaulted"},
                ])
            values: list[Any]
            if param_type in {"integer", "number", "float"}:
                values = [-1, 0, "boundary-1", "boundary", "boundary+1", "very_large", "wrong_type"]
            elif param_type in {"boolean", "bool"}:
                values = [True, False, 0, 1, "true", "false", None]
            else:
                values = ["", "whitespace", "very_long", "unicode_normalization_variant", "wrong_type"]
            parameter_tests.append({
                "step": name,
                "parameter": param_name,
                "test": "unconventional_values",
                "values": values,
                "expected": "business limits and normalization are enforced server-side",
            })
            if parameter.get("client_controlled") and (
                parameter.get("server_owned") or SENSITIVE_NAMES.search(param_name)
            ):
                client_trust_tests.append({
                    "step": name,
                    "parameter": param_name,
                    "test": "tamper_client_controlled_sensitive_value",
                    "expected": "server derives or integrity-checks the authoritative value",
                })

    return {
        "methodology": METHODOLOGY,
        "workflow": str(workflow.get("name") or "unnamed workflow"),
        "declared_invariants": [
            {"assertion": _assertion_label(item), "description": item.get("description", "")}
            for item in invariants
        ],
        "test_plan": {
            "client_side_trust": client_trust_tests,
            "unconventional_and_missing_input": parameter_tests,
            "workflow_sequence": sequence_tests,
            "domain_review": [
                "Map where prices, discounts, balances, limits, roles, and eligibility are calculated and revalidated.",
                "Check whether a state-dependent adjustment remains after its qualifying state is removed.",
                "Review encryption/decryption features only when another security decision consumes the same ciphertext format.",
                "Review email-domain decisions across every parser and normalization boundary.",
            ],
        },
        "confirmed_vulnerabilities": [],
        "note": "This is an offline hypothesis plan. A response difference or accepted odd input is not a logic-flaw finding without a violated business invariant.",
    }


def _stable(responses: list[Response]) -> bool:
    return bool(responses) and len({(item.status, item.body_sha1) for item in responses}) == 1


@dataclass
class WorkflowGateVerdict:
    confirmed: bool
    candidate: bool
    evidence: list[str]
    observations: dict[str, list[dict[str, Any]]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "confirmed": self.confirmed,
            "candidate": self.candidate,
            "evidence": self.evidence,
            "observations": self.observations,
            "next_steps": (
                ["Verify that the completed and fresh identities have equivalent entitlements and differ only in prerequisite workflow state."]
                if self.confirmed else
                ["Do not report a sequence bypass unless the completed control succeeds, the fresh identity reaches the same protected outcome, and anonymous does not."]
            ),
        }


def verify_workflow_gate(
    probe: Probe,
    *,
    url: str,
    completed_headers: dict[str, str],
    fresh_headers: dict[str, str],
    success_assertion: dict[str, Any],
    trials: int = 2,
) -> WorkflowGateVerdict:
    """Read-only forced-browsing oracle for a skipped workflow prerequisite."""
    assertion = _validate_assertion(success_assertion)
    if not 2 <= trials <= 5:
        raise ValueError("trials must be between 2 and 5")
    if completed_headers == fresh_headers:
        raise ValueError("completed and fresh workflow identities must be different")
    roles = {
        "completed_control": dict(completed_headers),
        "fresh_without_prerequisite": dict(fresh_headers),
        "anonymous_control": {},
    }
    responses: dict[str, list[Response]] = {name: [] for name in roles}
    assertions: dict[str, list[bool]] = {name: [] for name in roles}
    observations: dict[str, list[dict[str, Any]]] = {name: [] for name in roles}
    for _ in range(trials):
        for name, headers in roles.items():
            response = probe.send("GET", url, headers=headers)
            parsed = _parse_json(response)
            satisfied, _ = _evaluate(parsed, assertion) if parsed is not None else (False, _MISSING)
            responses[name].append(response)
            assertions[name].append(bool(_successful(response) and satisfied))
            observations[name].append(_observation(name, response, assertions[name][-1]))

    stable = {name: _stable(items) and len(set(assertions[name])) == 1 for name, items in responses.items()}
    completed_ok = stable["completed_control"] and all(assertions["completed_control"])
    fresh_ok = stable["fresh_without_prerequisite"] and all(assertions["fresh_without_prerequisite"])
    anonymous_denied = stable["anonymous_control"] and not any(assertions["anonymous_control"])
    anonymous_public = stable["anonymous_control"] and all(assertions["anonymous_control"])
    confirmed = bool(completed_ok and fresh_ok and anonymous_denied)
    candidate = bool(completed_ok and fresh_ok and not confirmed and not anonymous_public)
    evidence = [
        f"{name}: stable={stable[name]}, assertion={assertions[name][0]}, "
        f"status={responses[name][0].status}, body_sha1={responses[name][0].body_sha1[:12]}"
        for name in roles
    ]
    if confirmed:
        evidence.append(
            "Fresh authenticated workflow state reached the operator-defined protected outcome; completed control succeeded and anonymous control did not."
        )
    elif anonymous_public:
        evidence.append("Anonymous also reached the asserted outcome, so this is public behavior rather than a workflow-gate bypass.")
    elif candidate:
        evidence.append("Fresh and completed identities reached the outcome, but the anonymous control did not prove a protected workflow gate.")
    else:
        evidence.append("The skipped-prerequisite outcome was not reproduced with stable controls.")
    return WorkflowGateVerdict(confirmed, candidate, evidence, observations)


@dataclass
class LogicInvariantVerdict:
    confirmed: bool
    violated: list[str]
    restored: bool
    evidence: list[str]
    observations: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": METHODOLOGY,
            "confirmed": self.confirmed,
            "violated_invariants": self.violated,
            "restored": self.restored,
            "evidence": self.evidence,
            "observations": self.observations,
            "next_steps": (
                ["Reproduce once on the same disposable resource and document the concrete business/security impact of the violated invariant."]
                if self.confirmed else
                (["URGENT: restoration was not verified. Inspect and restore the test resource manually."] if self.violated and not self.restored else
                 ["Accepted input or a changed response is insufficient; no declared business invariant was proven false in persisted state."])
            ),
        }


def verify_logic_invariant(
    probe: Probe,
    *,
    action_url: str,
    state_url: str,
    action_method: str,
    action_body: dict[str, Any],
    invariants: list[dict[str, Any]],
    restore_url: str,
    restore_method: str,
    restore_body: dict[str, Any],
    identity_headers: dict[str, str] | None = None,
    volatile_paths: list[str] | None = None,
    confirm_state_change: bool = False,
) -> LogicInvariantVerdict:
    """Perform one reversible action and prove a persisted business-rule violation."""
    if not confirm_state_change:
        raise ValueError("confirm_state_change=true is required before any state-changing request")
    action_method = action_method.upper()
    restore_method = restore_method.upper()
    if action_method not in MUTATING_METHODS or restore_method not in MUTATING_METHODS:
        raise ValueError("action_method and restore_method must be POST, PUT, or PATCH; DELETE is never allowed")
    if not isinstance(action_body, dict) or not isinstance(restore_body, dict):
        raise ValueError("action_body and restore_body must be JSON objects")
    if not isinstance(invariants, list) or not invariants or len(invariants) > 25:
        raise ValueError("invariants must be a non-empty array with at most 25 assertions")
    for invariant in invariants:
        _validate_assertion(invariant)
    volatile_paths = list(volatile_paths or [])
    if len(volatile_paths) > 25 or any(not isinstance(path, str) or not path for path in volatile_paths):
        raise ValueError("volatile_paths must contain at most 25 non-empty dotted JSON paths")
    headers = dict(identity_headers or {})

    # Preflight every endpoint and method before the first mutation. In
    # particular, never discover after the action that restoration is forbidden
    # by scope or engagement rules.
    probe.scope.check(state_url)
    probe.scope.check(action_url)
    probe.scope.check(restore_url)
    probe.rules.enforce("GET", state_url)
    probe.rules.enforce(action_method, action_url)
    probe.rules.enforce(restore_method, restore_url)

    baseline_response = probe.send("GET", state_url, headers=headers)
    baseline_state = _parse_json(baseline_response)
    if not _successful(baseline_response) or not isinstance(baseline_state, (dict, list)):
        raise ValueError("state_url must return successful JSON before the action")
    baseline_results = [_evaluate(baseline_state, item) for item in invariants]
    if not all(result for result, _ in baseline_results):
        failed = [_assertion_label(item) for item, (result, _) in zip(invariants, baseline_results) if not result]
        raise ValueError(f"baseline already violates declared invariant(s): {failed}")
    normalized_baseline = _normalized_state(baseline_state, volatile_paths)

    observations: dict[str, Any] = {"baseline_read": _observation("baseline_read", baseline_response)}
    action_response: Response | None = None
    state_after_response: Response | None = None
    restore_response: Response | None = None
    restored_state_response: Response | None = None
    mutation_completed = False
    violated: list[str] = []
    restored = False
    try:
        action_response = probe.send(action_method, action_url, headers=headers, json=action_body)
        mutation_completed = True
        state_after_response = probe.send("GET", state_url, headers=headers)
        state_after = _parse_json(state_after_response)
        if _successful(state_after_response) and isinstance(state_after, (dict, list)):
            violated = [
                _assertion_label(item)
                for item in invariants
                if not _evaluate(state_after, item)[0]
            ]
    finally:
        if mutation_completed:
            restore_response = probe.send(restore_method, restore_url, headers=headers, json=restore_body)
            restored_state_response = probe.send("GET", state_url, headers=headers)
            restored_state = _parse_json(restored_state_response)
            if _successful(restored_state_response) and isinstance(restored_state, (dict, list)):
                restored_results = [_evaluate(restored_state, item) for item in invariants]
                restored = bool(
                    all(result for result, _ in restored_results)
                    and _normalized_state(restored_state, volatile_paths) == normalized_baseline
                )

    if action_response:
        observations["action"] = _observation("action", action_response)
    if state_after_response:
        observations["state_after_action"] = _observation("state_after_action", state_after_response)
    if restore_response:
        observations["restore_action"] = _observation("restore_action", restore_response)
    if restored_state_response:
        observations["restored_state"] = _observation("restored_state", restored_state_response)
    evidence = [
        f"Baseline satisfied {len(invariants)} declared invariant(s).",
        f"Action response status={action_response.status if action_response else 'not sent'}; persisted violated invariants={violated}.",
        "The full JSON state, excluding explicitly declared volatile paths, matched baseline after restoration."
        if restored else "Restoration to the baseline JSON state was not verified.",
    ]
    return LogicInvariantVerdict(
        confirmed=bool(violated and restored),
        violated=violated,
        restored=restored,
        evidence=evidence,
        observations=observations,
    )
