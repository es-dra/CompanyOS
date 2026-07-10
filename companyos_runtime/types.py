"""Strict public runtime contracts and canonical serialization helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Iterable, Mapping

from .errors import ContractError


class GoalState(StrEnum):
    """Immutable state of a compiled GoalSpec projection.

    Run and Task objects own executable lifecycle. CompanyOS v0.2 deliberately
    does not infer an aggregate goal lifecycle across one or more runs.
    """

    COMPILED = "compiled"


class LoopState(StrEnum):
    INTAKE = "intake"
    COMPILED = "compiled"
    READY = "ready"
    RUNNING = "running"
    SUSPENDED = "suspended_for_input"
    EVIDENCE_PENDING = "evidence_pending"
    INTEGRATION_PENDING = "integration_pending"
    CI_PENDING = "ci_pending"
    DEPLOY_DIR_UPDATED = "deploy_dir_updated"
    RUNTIME_STALE = "runtime_stale"
    RUNTIME_CHECK_PENDING = "runtime_check_pending"
    RUNTIME_FRESH = "runtime_freshness_verified"
    IMPROVEMENT_PENDING = "improvement_pending"
    DELIVERED = "delivered"
    BLOCKED_DECISION = "blocked_with_decision"
    BLOCKED_MISSING_STATE = "blocked_with_missing_state"
    BLOCKED_CAPABILITY = "blocked_with_capability_gap"


class LoopEvent(StrEnum):
    OWNER_INTENT_RECEIVED = "owner_intent_received"
    GOAL_COMPILED = "goal_compiled"
    RUN_READY = "run_ready"
    TASK_STARTED = "task_started"
    HUMAN_APPROVAL_REQUESTED = "human_approval_requested"
    HUMAN_APPROVAL_RECEIVED = "human_approval_received"
    EVIDENCE_SUBMITTED = "evidence_submitted"
    EVALUATOR_VERDICT_RECEIVED = "evaluator_verdict_received"
    CI_CHECK_STARTED = "ci_check_started"
    CI_CHECK_COMPLETED = "ci_check_completed"
    DEPLOY_DIRECTORY_UPDATED = "deploy_directory_updated"
    SERVICE_RESTART_ATTEMPTED = "service_restart_attempted"
    RUNTIME_FRESHNESS_VERIFIED = "runtime_freshness_verified"
    RUNTIME_DRIFT_DETECTED = "runtime_drift_detected"
    CAPABILITY_GAP_DETECTED = "capability_gap_detected"
    MISSING_STATE_DETECTED = "missing_state_detected"
    CIRCUIT_BREAKER_TRIGGERED = "circuit_breaker_triggered"
    IMPROVEMENT_REQUESTED = "improvement_requested"
    DELIVERY_CONFIRMED = "delivery_confirmed"
    RESUME_REQUESTED = "resume_requested"


class TaskState(StrEnum):
    READY = "ready"
    LEASED = "leased"
    RUNNING = "running"
    SUSPENDED = "suspended_for_input"
    EVIDENCE_PENDING = "evidence_pending"
    EVALUATOR_PENDING = "evaluator_pending"
    INTEGRATION_PENDING = "integration_pending"
    DELIVERED = "delivered"
    RETRY_PENDING = "retry_pending"
    FAILED = "failed"
    BLOCKED = "blocked_with_decision"
    CANCELED = "canceled"
    DELETED = "deleted"
    RETIRED = "retired"


class EvidenceState(StrEnum):
    STRUCTURE = "structure_verification"
    RUNTIME = "runtime_verification"
    PROVIDER_SMOKE = "provider_smoke"
    HUMAN_ACCEPTANCE = "human_acceptance"
    BUSINESS_VALIDATION = "business_validation"
    DURABLE_MEMORY_PROMOTION = "durable_memory_promotion"
    ACTIVE_RULE_PROMOTION = "active_rule_promotion"

    @classmethod
    def parse(cls, value: str) -> "EvidenceState":
        if value == "durable_rule_promotion":
            raise ContractError(
                "durable_rule_promotion is a legacy, semantically distinct state; "
                "migrate it explicitly to active_rule_promotion evidence instead of mapping it to memory promotion"
            )
        try:
            return cls(value)
        except ValueError as exc:
            raise ContractError(f"unsupported evidence state: {value}") from exc


class Capability(StrEnum):
    READ_LOCAL = "read_local"
    WRITE_LOCAL = "write_local"
    NETWORK = "network"
    EXTERNAL_DOWNLOAD = "external_download"
    REPO_REMOTE = "repo_remote"
    SERVER_READ = "server_read"
    SERVER_WRITE = "server_write"
    PROVIDER_COST = "provider_cost"
    PUBLIC_RELEASE = "public_release"
    DESTRUCTIVE = "destructive"
    DURABLE_MEMORY_PROMOTION = "durable_memory_promotion"
    ACTIVE_RULE_PROMOTION = "active_rule_promotion"
    CONTROL_RESUME = "control_resume"


class IntegrationState(StrEnum):
    REVIEW_PENDING = "review_pending"
    EVALUATOR_PENDING = "evaluator_pending"
    PUSH_PR_PENDING = "push_pr_pending"
    CI_PENDING = "ci_pending"
    CI_FAILED = "ci_failed"
    MERGE_PENDING = "merge_pending"
    DEPLOY_PENDING = "deploy_pending"
    DEPLOY_DIR_UPDATED = "deploy_dir_updated"
    SERVICE_RESTART_REQUIRED = "service_restart_required"
    RUNTIME_CHECK_PENDING = "runtime_check_pending"
    RUNTIME_STALE = "runtime_stale"
    DELETE_PENDING = "delete_pending"
    RETIRE_PENDING = "retire_pending"
    DELIVERED = "delivered"
    DEFER_WITH_OWNER = "defer_with_owner"
    SUPERSEDED = "superseded"


class EvaluatorVerdict(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    PASS = "pass"
    FAIL = "fail"
    PASS_WITH_RISK = "pass_with_residual_risk"
    BLOCKED = "blocked_with_decision"


class ProposalState(StrEnum):
    CANDIDATE = "candidate"
    HELDOUT_PENDING = "heldout_pending"
    OWNER_REVIEW = "owner_review"
    LIMITED = "limited"
    ACTIVE = "active"
    REJECTED = "rejected"
    RETIRED = "retired"


TERMINAL_TASK_STATES = {
    TaskState.DELIVERED,
    TaskState.CANCELED,
    TaskState.DELETED,
    TaskState.RETIRED,
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(value: Any) -> str:
    raw = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _strict_keys(
    data: Mapping[str, Any], required: Iterable[str], allowed: Iterable[str], label: str
) -> None:
    required_set = set(required)
    allowed_set = set(allowed)
    missing = required_set - data.keys()
    unknown = data.keys() - allowed_set
    if missing:
        raise ContractError(f"{label} missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unknown fields: {sorted(unknown)}")


def _non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field_name} must be a non-empty string")
    return value.strip()


def _string_list(
    value: Any, field_name: str, *, allow_empty: bool = True
) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ContractError(f"{field_name} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise ContractError(f"{field_name} must not be empty")
    result = tuple(item.strip() for item in value)
    if len(result) != len(set(result)):
        raise ContractError(f"{field_name} must not contain duplicates")
    return result


@dataclass(frozen=True)
class RuntimeSurfaceSpec:
    """Exact runtime target and trusted probe contract for freshness gates."""

    surface_key: str
    target_identity: str
    allowed_probes: tuple[str, ...]
    max_ttl_seconds: int = 300
    trigger_event_required: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuntimeSurfaceSpec":
        allowed = {
            "surface_key",
            "target_identity",
            "allowed_probes",
            "max_ttl_seconds",
            "trigger_event_required",
        }
        _strict_keys(
            data,
            {"surface_key", "target_identity", "allowed_probes"},
            allowed,
            "runtime_surface_spec",
        )
        ttl = data.get("max_ttl_seconds", 300)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 86400:
            raise ContractError("max_ttl_seconds must be an integer from 1 to 86400")
        trigger_required = data.get("trigger_event_required", True)
        if not isinstance(trigger_required, bool):
            raise ContractError("trigger_event_required must be a boolean")
        return cls(
            surface_key=_non_empty_string(data["surface_key"], "surface_key"),
            target_identity=_non_empty_string(
                data["target_identity"], "target_identity"
            ),
            allowed_probes=_string_list(
                data["allowed_probes"], "allowed_probes", allow_empty=False
            ),
            max_ttl_seconds=ttl,
            trigger_event_required=trigger_required,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_key": self.surface_key,
            "target_identity": self.target_identity,
            "allowed_probes": list(self.allowed_probes),
            "max_ttl_seconds": self.max_ttl_seconds,
            "trigger_event_required": self.trigger_event_required,
        }


def _runtime_surfaces(value: Any, field_name: str) -> tuple[RuntimeSurfaceSpec, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{field_name} must be a list of runtime surface objects")
    if not all(isinstance(item, Mapping) for item in value):
        raise ContractError(f"{field_name} must contain only runtime surface objects")
    surfaces = tuple(RuntimeSurfaceSpec.from_dict(item) for item in value)
    keys = [item.surface_key for item in surfaces]
    if len(keys) != len(set(keys)):
        raise ContractError(
            f"{field_name} must not contain duplicate surface_key values"
        )
    return surfaces


def _workflow_steps(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not all(
        isinstance(step, Mapping) for step in value
    ):
        raise ContractError("workflow_steps must be a list of objects")
    required = {"step_id", "adapter", "action", "resource", "request_digest"}
    normalized: list[dict[str, Any]] = []
    for index, step in enumerate(value):
        _strict_keys(step, required, required, f"workflow_steps[{index}]")
        digest = _non_empty_string(
            step["request_digest"], f"workflow_steps[{index}].request_digest"
        )
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ContractError(
                f"workflow_steps[{index}].request_digest must be lowercase SHA-256 hex"
            )
        normalized.append(
            {
                "step_id": _non_empty_string(
                    step["step_id"], f"workflow_steps[{index}].step_id"
                ),
                "adapter": _non_empty_string(
                    step["adapter"], f"workflow_steps[{index}].adapter"
                ),
                "action": _non_empty_string(
                    step["action"], f"workflow_steps[{index}].action"
                ),
                "resource": _non_empty_string(
                    step["resource"], f"workflow_steps[{index}].resource"
                ),
                "request_digest": digest,
            }
        )
    step_ids = [step["step_id"] for step in normalized]
    if len(step_ids) != len(set(step_ids)):
        raise ContractError("workflow_steps require unique step_id values")
    return tuple(normalized)


@dataclass(frozen=True)
class GoalSpec:
    goal_id: str
    target_outcome: str
    success_evidence_states: tuple[EvidenceState, ...]
    read_scope: tuple[str, ...] = ()
    write_scope: tuple[str, ...] = ()
    forbidden_scope: tuple[str, ...] = ()
    allowed_capabilities: tuple[Capability, ...] = (Capability.READ_LOCAL,)
    required_runtime_surfaces: tuple[RuntimeSurfaceSpec, ...] = ()
    evaluator_required: bool = False
    max_iterations_without_evidence: int = 3
    provider_budget_minor_units: int = 0
    provider_call_limit: int = 0
    budget_currency: str = "USD"
    non_goals: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GoalSpec":
        allowed = {
            "goal_id",
            "target_outcome",
            "success_evidence_states",
            "read_scope",
            "write_scope",
            "forbidden_scope",
            "allowed_capabilities",
            "required_runtime_surfaces",
            "evaluator_required",
            "max_iterations_without_evidence",
            "provider_budget_minor_units",
            "provider_call_limit",
            "budget_currency",
            "non_goals",
        }
        _strict_keys(
            data,
            {"goal_id", "target_outcome", "success_evidence_states"},
            allowed,
            "goal_spec",
        )
        evidence = _string_list(
            data["success_evidence_states"],
            "success_evidence_states",
            allow_empty=False,
        )
        try:
            evidence_states = tuple(EvidenceState.parse(item) for item in evidence)
            capabilities = tuple(
                Capability(item)
                for item in data.get("allowed_capabilities", ["read_local"])
            )
        except ValueError as exc:
            raise ContractError(str(exc)) from exc
        iterations = data.get("max_iterations_without_evidence", 3)
        if (
            isinstance(iterations, bool)
            or not isinstance(iterations, int)
            or iterations < 1
        ):
            raise ContractError(
                "max_iterations_without_evidence must be a positive integer"
            )
        evaluator_required = data.get("evaluator_required", False)
        if not isinstance(evaluator_required, bool):
            raise ContractError("evaluator_required must be a boolean")
        if len(capabilities) != len(set(capabilities)):
            raise ContractError("allowed_capabilities must not contain duplicates")
        budget = data.get("provider_budget_minor_units", 0)
        calls = data.get("provider_call_limit", 0)
        if isinstance(budget, bool) or not isinstance(budget, int) or budget < 0:
            raise ContractError(
                "provider_budget_minor_units must be a non-negative integer"
            )
        if isinstance(calls, bool) or not isinstance(calls, int) or calls < 0:
            raise ContractError("provider_call_limit must be a non-negative integer")
        currency = _non_empty_string(
            data.get("budget_currency", "USD"), "budget_currency"
        ).upper()
        if len(currency) != 3 or not currency.isalpha() or not currency.isascii():
            raise ContractError(
                "budget_currency must be a three-letter ASCII currency code"
            )
        return cls(
            goal_id=_non_empty_string(data["goal_id"], "goal_id"),
            target_outcome=_non_empty_string(data["target_outcome"], "target_outcome"),
            success_evidence_states=evidence_states,
            read_scope=_string_list(data.get("read_scope", []), "read_scope"),
            write_scope=_string_list(data.get("write_scope", []), "write_scope"),
            forbidden_scope=_string_list(
                data.get("forbidden_scope", []), "forbidden_scope"
            ),
            allowed_capabilities=capabilities,
            required_runtime_surfaces=_runtime_surfaces(
                data.get("required_runtime_surfaces", []), "required_runtime_surfaces"
            ),
            evaluator_required=evaluator_required,
            max_iterations_without_evidence=iterations,
            provider_budget_minor_units=budget,
            provider_call_limit=calls,
            budget_currency=currency,
            non_goals=_string_list(data.get("non_goals", []), "non_goals"),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["success_evidence_states"] = [
            item.value for item in self.success_evidence_states
        ]
        data["allowed_capabilities"] = [
            item.value for item in self.allowed_capabilities
        ]
        for key in ("read_scope", "write_scope", "forbidden_scope", "non_goals"):
            data[key] = list(data[key])
        data["required_runtime_surfaces"] = [
            item.to_dict() for item in self.required_runtime_surfaces
        ]
        return data


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    goal_id: str
    objective: str
    expected_delta: str
    primary_surface: str
    evidence_target: EvidenceState
    capabilities: tuple[Capability, ...] = (Capability.READ_LOCAL,)
    read_scope: tuple[str, ...] = ()
    write_scope: tuple[str, ...] = ()
    forbidden_scope: tuple[str, ...] = ()
    required_runtime_surfaces: tuple[RuntimeSurfaceSpec, ...] = ()
    evaluator_required: bool = False
    integration_required: bool = True
    workflow_steps: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    max_attempts: int = 3

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskSpec":
        allowed = {
            "task_id",
            "goal_id",
            "objective",
            "expected_delta",
            "primary_surface",
            "evidence_target",
            "capabilities",
            "read_scope",
            "write_scope",
            "forbidden_scope",
            "required_runtime_surfaces",
            "evaluator_required",
            "integration_required",
            "workflow_steps",
            "max_attempts",
        }
        required = {
            "task_id",
            "goal_id",
            "objective",
            "expected_delta",
            "primary_surface",
            "evidence_target",
        }
        _strict_keys(data, required, allowed, "task_spec")
        try:
            target = EvidenceState.parse(data["evidence_target"])
            capabilities = tuple(
                Capability(item) for item in data.get("capabilities", ["read_local"])
            )
        except (TypeError, ValueError) as exc:
            raise ContractError(str(exc)) from exc
        steps = _workflow_steps(data.get("workflow_steps", []))
        max_attempts = data.get("max_attempts", 3)
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            raise ContractError("max_attempts must be a positive integer")
        evaluator_required = data.get("evaluator_required", False)
        if not isinstance(evaluator_required, bool):
            raise ContractError("evaluator_required must be a boolean")
        if len(capabilities) != len(set(capabilities)):
            raise ContractError("capabilities must not contain duplicates")
        integration_required = data.get("integration_required", True)
        if not isinstance(integration_required, bool):
            raise ContractError("integration_required must be a boolean")
        return cls(
            task_id=_non_empty_string(data["task_id"], "task_id"),
            goal_id=_non_empty_string(data["goal_id"], "goal_id"),
            objective=_non_empty_string(data["objective"], "objective"),
            expected_delta=_non_empty_string(data["expected_delta"], "expected_delta"),
            primary_surface=_non_empty_string(
                data["primary_surface"], "primary_surface"
            ),
            evidence_target=target,
            capabilities=capabilities,
            read_scope=_string_list(data.get("read_scope", []), "read_scope"),
            write_scope=_string_list(data.get("write_scope", []), "write_scope"),
            forbidden_scope=_string_list(
                data.get("forbidden_scope", []), "forbidden_scope"
            ),
            required_runtime_surfaces=_runtime_surfaces(
                data.get("required_runtime_surfaces", []), "required_runtime_surfaces"
            ),
            evaluator_required=evaluator_required,
            integration_required=integration_required,
            workflow_steps=steps,
            max_attempts=max_attempts,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_target"] = self.evidence_target.value
        data["capabilities"] = [item.value for item in self.capabilities]
        for key in ("read_scope", "write_scope", "forbidden_scope"):
            data[key] = list(data[key])
        data["required_runtime_surfaces"] = [
            item.to_dict() for item in self.required_runtime_surfaces
        ]
        data["workflow_steps"] = [dict(step) for step in self.workflow_steps]
        return data
