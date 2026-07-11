"""Fail-closed compiler from human authoring packets to runtime contracts."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Set as AbstractSet
from typing import Any, Mapping

from .errors import ContractError
from .scope import validate_goal_scope, validate_task_within_goal
from .types import GoalSpec, TaskSpec, content_hash


_OPEN_VALUES = {
    True,
    "open",
    "allowed",
    "scoped_open",
    "write_allowed",
    "push_pr_allowed",
}
_GATE_CAPABILITIES = {
    "network": "network",
    "external_download": "external_download",
    "repo_remote": "repo_remote",
    "server_write": "server_write",
    "provider": "provider_cost",
    "public_release": "public_release",
    "destructive_operations": "destructive",
}
_CLOSED_VALUES = {None, False, "closed", "denied", "none"}
_EVALUATOR_POLICIES = {
    "not_required",
    "required_before_integration",
    "required_before_claim",
}

# These sets are part of the public authoring contract.  Keep them named so
# repository validation can prove that the JSON Schema, templates, and the
# fail-closed compiler accept the same surface.
GOAL_EXECUTABLE_FIELDS = frozenset(
    {
        "goal_id",
        "target_outcome",
        "success_evidence_states",
        "owner_authority",
        "required_runtime_surfaces",
        "evaluator_required",
        "circuit_breakers",
        "non_goals",
    }
)
GOAL_CONTEXTUAL_FIELDS = frozenset(
    {
        "source_request",
        "context_pack",
        "project_adoption_ref",
        "integration_policy",
        "stop_routes",
        "closeout_shape",
    }
)
GOAL_AUTHORITY_FIELDS = frozenset(
    {"read_scope", "write_scope", "forbidden_scope", "allowed_capabilities"}
)
GOAL_CIRCUIT_BREAKER_FIELDS = frozenset(
    {"max_iterations_without_new_evidence", "provider_budget"}
)
PROVIDER_BUDGET_FIELDS = frozenset({"currency", "max_minor_units", "max_calls"})
TASK_EXECUTABLE_FIELDS = frozenset(
    {
        "task_id",
        "parent_goal_id",
        "objective",
        "expected_delta",
        "primary_artifact_or_surface",
        "read_scope",
        "write_scope",
        "forbidden_scope",
        "capabilities",
        "evaluator_policy",
        "evaluator_required",
        "integration_required",
        "required_runtime_surfaces",
        "gates",
        "workflow_steps",
        "evidence_target",
        "max_attempts",
    }
)
TASK_CONTEXTUAL_FIELDS = frozenset(
    {
        "dirty_boundary",
        "worktree_policy",
        "worker_policy",
        "procedure",
        "verification_route",
        "integration_route",
        "stop_conditions",
        "close_condition",
        "delete_or_retire_condition",
        "requirement_closure_map",
        "non_claims",
    }
)


@dataclass(frozen=True)
class CompilationResult:
    kind: str
    source_digest: str
    compiled: Mapping[str, Any]
    non_executable_authoring_fields: tuple[str, ...]
    warnings: tuple[str, ...]


def _object(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be an object")
    return value


def _reject_unknown(
    value: Mapping[str, Any], allowed: AbstractSet[str], field: str
) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ContractError(f"{field} contains unsupported fields: {sorted(unknown)}")


def compile_goal(authoring: Mapping[str, Any]) -> tuple[GoalSpec, CompilationResult]:
    source = _object(authoring, "goal authoring packet")
    if "goal_contract" not in source:
        spec = GoalSpec.from_dict(source)
        validate_goal_scope(spec)
        return spec, CompilationResult(
            kind="GoalSpec",
            source_digest=content_hash(source),
            compiled=spec.to_dict(),
            non_executable_authoring_fields=(),
            warnings=(),
        )
    packet = _object(source["goal_contract"], "goal_contract")
    authority = _object(packet.get("owner_authority", {}), "owner_authority")
    breakers = _object(packet.get("circuit_breakers", {}), "circuit_breakers")
    executable = GOAL_EXECUTABLE_FIELDS
    contextual = GOAL_CONTEXTUAL_FIELDS
    _reject_unknown(packet, executable | contextual, "goal_contract")
    _reject_unknown(
        authority,
        set(GOAL_AUTHORITY_FIELDS),
        "owner_authority",
    )
    _reject_unknown(
        breakers,
        set(GOAL_CIRCUIT_BREAKER_FIELDS),
        "circuit_breakers",
    )
    provider_budget = _object(
        breakers.get("provider_budget", {}), "circuit_breakers.provider_budget"
    )
    _reject_unknown(
        provider_budget,
        set(PROVIDER_BUDGET_FIELDS),
        "circuit_breakers.provider_budget",
    )
    compiled = {
        "goal_id": packet.get("goal_id"),
        "target_outcome": packet.get("target_outcome"),
        "success_evidence_states": packet.get("success_evidence_states", []),
        "read_scope": authority.get("read_scope", []),
        "write_scope": authority.get("write_scope", []),
        "forbidden_scope": authority.get("forbidden_scope", []),
        "allowed_capabilities": authority.get("allowed_capabilities", ["read_local"]),
        "required_runtime_surfaces": packet.get("required_runtime_surfaces", []),
        "evaluator_required": packet.get("evaluator_required", False),
        "max_iterations_without_evidence": breakers.get(
            "max_iterations_without_new_evidence", 3
        ),
        "provider_budget_minor_units": provider_budget.get("max_minor_units", 0),
        "provider_call_limit": provider_budget.get("max_calls", 0),
        "budget_currency": provider_budget.get("currency", "USD"),
        "non_goals": packet.get("non_goals", []),
    }
    spec = GoalSpec.from_dict(compiled)
    validate_goal_scope(spec)
    ignored = tuple(sorted(set(packet) - executable))
    warnings = tuple(
        f"authoring field is contextual, not executable authority: {name}"
        for name in ignored
    )
    return spec, CompilationResult(
        kind="GoalSpec",
        source_digest=content_hash(source),
        compiled=spec.to_dict(),
        non_executable_authoring_fields=ignored,
        warnings=warnings,
    )


def compile_task(
    authoring: Mapping[str, Any],
    *,
    goal: GoalSpec,
) -> tuple[TaskSpec, CompilationResult]:
    source = _object(authoring, "task authoring packet")
    if "task_packet" not in source:
        spec = TaskSpec.from_dict(source)
        validate_task_within_goal(goal, spec)
        return spec, CompilationResult(
            kind="TaskSpec",
            source_digest=content_hash(source),
            compiled=spec.to_dict(),
            non_executable_authoring_fields=(),
            warnings=(),
        )
    packet = _object(source["task_packet"], "task_packet")
    executable = TASK_EXECUTABLE_FIELDS
    contextual = TASK_CONTEXTUAL_FIELDS
    _reject_unknown(packet, executable | contextual, "task_packet")
    evaluator_policy = packet.get("evaluator_policy", "not_required")
    if evaluator_policy not in _EVALUATOR_POLICIES:
        raise ContractError(
            "evaluator_policy must be one of: " + ", ".join(sorted(_EVALUATOR_POLICIES))
        )
    evaluator_required = evaluator_policy in {
        "required_before_integration",
        "required_before_claim",
    }
    capabilities = packet.get("capabilities", ["read_local"])
    if not isinstance(capabilities, list):
        raise ContractError("capabilities must be a list")
    gates = _object(packet.get("gates", {}), "gates")
    unknown_gates = set(gates) - set(_GATE_CAPABILITIES)
    if unknown_gates:
        raise ContractError(f"unsupported gates: {sorted(unknown_gates)}")
    for gate, capability in _GATE_CAPABILITIES.items():
        if gate not in gates:
            if capability in capabilities:
                raise ContractError(
                    f"capability {capability} requires explicit open gate {gate}; "
                    "missing gates are closed"
                )
            continue
        gate_value = gates[gate]
        if gate_value not in _OPEN_VALUES and gate_value not in _CLOSED_VALUES:
            raise ContractError(f"gate {gate} has unsupported state: {gate_value!r}")
        if gate_value in _OPEN_VALUES and capability not in capabilities:
            raise ContractError(
                f"gate {gate} is open but exact capability {capability} is absent"
            )
        if gate_value in _CLOSED_VALUES and capability in capabilities:
            raise ContractError(
                f"gate {gate} is closed but capability {capability} is present"
            )
    explicit_evaluator = packet.get("evaluator_required")
    if explicit_evaluator is not None:
        if not isinstance(explicit_evaluator, bool):
            raise ContractError("evaluator_required must be a boolean")
        if explicit_evaluator is not evaluator_required:
            raise ContractError(
                "evaluator_required contradicts evaluator_policy; policy is authoritative"
            )
    compiled = {
        "task_id": packet.get("task_id"),
        "goal_id": packet.get("parent_goal_id"),
        "objective": packet.get("objective"),
        "expected_delta": packet.get("expected_delta"),
        "primary_surface": packet.get("primary_artifact_or_surface"),
        "evidence_target": packet.get("evidence_target"),
        "capabilities": capabilities,
        "read_scope": packet.get("read_scope", []),
        "write_scope": packet.get("write_scope", []),
        "forbidden_scope": packet.get("forbidden_scope", []),
        "required_runtime_surfaces": packet.get("required_runtime_surfaces", []),
        "evaluator_required": evaluator_required,
        "integration_required": packet.get("integration_required", True),
        "workflow_steps": packet.get("workflow_steps", []),
        "max_attempts": packet.get("max_attempts", 3),
    }
    spec = TaskSpec.from_dict(compiled)
    validate_task_within_goal(goal, spec)
    ignored = tuple(sorted(set(packet) - executable))
    warnings = tuple(
        f"authoring field is contextual, not executable authority: {name}"
        for name in ignored
    )
    return spec, CompilationResult(
        kind="TaskSpec",
        source_digest=content_hash(source),
        compiled=spec.to_dict(),
        non_executable_authoring_fields=ignored,
        warnings=warnings,
    )
