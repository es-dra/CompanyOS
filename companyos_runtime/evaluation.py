"""Held-in/held-out evaluation and approval-gated improvement proposals."""

from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol

from .errors import (
    AuthorizationError,
    ContractError,
    EvidenceError,
    IntegrityError,
    NotFoundError,
    TransitionError,
)
from .evidence import classify_promotion_provenance
from .identity import IdentityManager, Role, VerifiedPrincipal
from .scope import normalize_scope
from .store import SQLiteStore, protected_authority_config_digest
from .types import (
    Capability,
    EvidenceState,
    EvaluatorVerdict,
    LoopState,
    ProposalState,
    TaskSpec,
    TaskState,
    canonical_json,
    content_hash,
    utc_now,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SPLITS = {"held_in", "held_out", "sealed"}
_EVAL_STATUSES = {"pass", "fail", "error"}
_EDITABLE_SURFACES = {
    "prompt_candidate",
    "context_selection",
    "workflow_parameter",
    "evaluator_threshold",
    "memory_candidate",
    "routing_candidate",
}
_PROTECTED_SURFACES = {
    "authority_order",
    "capability_policy",
    "event_store",
    "event_integrity",
    "heldout_dataset",
    "evaluator_code",
    "security_policy",
    "secrets",
}
_ACTUAL_OUTCOME_KINDS = {
    "benefit",
    "friction_reduction",
    "failure_found",
    "failure_prevented",
}
_VERIFICATION_STATES = {
    EvidenceState.STRUCTURE.value,
    EvidenceState.RUNTIME.value,
}
_PASSING_EVALUATOR_VERDICTS = {
    EvaluatorVerdict.PASS.value,
    EvaluatorVerdict.PASS_WITH_RISK.value,
}
_ACTIVE_RULE_NON_CLAIM = (
    "structure-verified single-host promotion record with a verifier-accepted "
    "external-custody envelope only; no human acceptance, business validation, "
    "legal conclusion, public release, production autonomy, or real external "
    "custody service claim"
)


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value.strip()


def _digest(value: str, field: str) -> str:
    result = _text(value, field).lower()
    if not _SHA256.fullmatch(result):
        raise ContractError(f"{field} must be a lowercase SHA-256 hex digest")
    return result


def _metrics(value: Mapping[str, Any]) -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise ContractError("metrics must be an object")
    result: dict[str, float] = {}
    for key, item in value.items():
        name = _text(key, "metric name")
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ContractError(f"metric must be numeric: {name}")
        number = float(item)
        if not math.isfinite(number):
            raise ContractError(f"metric must be finite: {name}")
        result[name] = number
    return result


def _instant(value: str, field: str) -> datetime:
    text = _text(value, field)
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} must be an RFC 3339 timestamp") from exc
    if result.tzinfo is None:
        raise ContractError(f"{field} must include a timezone")
    return result


def _verifier_authority_id(verifier: object) -> str:
    """Bind a declared verifier identity to its concrete implementation type."""

    explicit = getattr(verifier, "authority_id", None)
    if not isinstance(explicit, str) or not explicit.strip():
        raise AuthorizationError(
            "trusted verifier must expose a non-empty authority_id"
        )
    verifier_type = type(verifier)
    return content_hash(
        {
            "authority_contract": "verifier-implementation-v2",
            "implementation_module": verifier_type.__module__,
            "implementation_qualname": verifier_type.__qualname__,
            "declared_authority_id": explicit.strip(),
        }
    )


def _strings(value: Iterable[str], field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise ContractError(f"{field} must be an array of strings")
    result = tuple(_text(item, field) for item in value)
    if not result:
        raise ContractError(f"{field} must not be empty")
    if len(result) != len(set(result)):
        raise ContractError(f"{field} must contain unique strings")
    return result


def _bounded_scope(value: str, project_id: str) -> str:
    scope = _text(value, "scope")
    normalized = normalize_scope(scope)
    expected_prefix = f"project://{_text(project_id, 'project_id')}/"
    if (
        normalized != scope
        or not scope.startswith(expected_prefix)
        or scope == expected_prefix
        or "*" in scope
        or ".." in scope.split("/")
    ):
        raise ContractError(
            "limited scope must be an exact, non-wildcard project://<project>/... scope"
        )
    return scope


@dataclass(frozen=True, slots=True)
class LimitedRulePromotionRequest:
    """Frozen candidate->limited decision input used for exact Owner approval."""

    candidate_id: str
    candidate_digest: str
    policy_version: str
    target_state: str
    source_run_id: str
    source_task_id: str
    verification_evidence_id: str
    verification_evidence_digest: str
    verification_evidence_state: str
    verification_evaluator_verdict: str
    promotion_validation_eval_id: str
    promotion_validation_dataset_digest: str
    promotion_validation_attestation_digest: str
    promotion_validation_query_count: int
    promotion_validation_status: str
    scope: str
    actual_outcome_kind: str
    actual_outcome: str
    risk: str
    non_goals: tuple[str, ...]
    review_condition: str
    rollback_or_retirement_path: str
    non_claim_boundary: str

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "policy_version",
            "target_state",
            "source_run_id",
            "source_task_id",
            "verification_evidence_id",
            "verification_evidence_state",
            "verification_evaluator_verdict",
            "promotion_validation_eval_id",
            "promotion_validation_status",
            "scope",
            "actual_outcome_kind",
            "actual_outcome",
            "risk",
            "review_condition",
            "rollback_or_retirement_path",
            "non_claim_boundary",
        ):
            value = getattr(self, name)
            if _text(value, name) != value:
                raise ContractError(f"{name} must not contain surrounding whitespace")
        for name in (
            "candidate_digest",
            "verification_evidence_digest",
            "promotion_validation_dataset_digest",
            "promotion_validation_attestation_digest",
        ):
            value = getattr(self, name)
            if _digest(value, name) != value:
                raise ContractError(f"{name} must be canonical")
        if self.target_state != ProposalState.LIMITED.value:
            raise ContractError("limited request target_state must be limited")
        if self.verification_evidence_state not in _VERIFICATION_STATES:
            raise ContractError(
                "limited promotion requires structure/runtime verification evidence"
            )
        if self.verification_evaluator_verdict not in _PASSING_EVALUATOR_VERDICTS:
            raise ContractError(
                "limited promotion verification evidence must have a passing evaluator verdict"
            )
        if self.promotion_validation_status != "pass":
            raise ContractError("promotion_validation_status must be pass")
        if (
            isinstance(self.promotion_validation_query_count, bool)
            or not isinstance(self.promotion_validation_query_count, int)
            or self.promotion_validation_query_count < 1
        ):
            raise ContractError(
                "promotion_validation_query_count must be a positive integer"
            )
        _bounded_scope(self.scope, self._scope_project_id())
        if self.actual_outcome_kind not in _ACTUAL_OUTCOME_KINDS:
            raise ContractError(
                "actual_outcome_kind must be benefit, friction_reduction, "
                "failure_found, or failure_prevented"
            )
        normalized_non_goals = _strings(self.non_goals, "non_goal")
        if normalized_non_goals != self.non_goals:
            raise ContractError("non_goals must be canonical")

    def _scope_project_id(self) -> str:
        return self.scope[len("project://") :].split("/", 1)[0]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["non_goals"] = list(self.non_goals)
        return result

    @property
    def request_digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LimitedRulePromotionRequest":
        if not isinstance(value, Mapping):
            raise ContractError("limited rule promotion request must be an object")
        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ContractError(
                "limited rule promotion request fields mismatch: "
                f"missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
        values = dict(value)
        raw_non_goals = values["non_goals"]
        if not isinstance(raw_non_goals, list):
            raise ContractError("non_goals must be an array")
        values["non_goals"] = tuple(raw_non_goals)
        return cls(**values)


@dataclass(frozen=True, slots=True)
class LimitedRulePromotionRecord:
    """Canonical event snapshot for the bounded candidate->limited gate."""

    promotion_record_id: str
    request: LimitedRulePromotionRequest
    from_state: str
    owner_approval_id: str
    owner_principal_id: str
    approved_at: str

    def __post_init__(self) -> None:
        for name in (
            "promotion_record_id",
            "from_state",
            "owner_approval_id",
            "owner_principal_id",
            "approved_at",
        ):
            value = getattr(self, name)
            if _text(value, name) != value:
                raise ContractError(f"{name} must not contain surrounding whitespace")
        if not isinstance(self.request, LimitedRulePromotionRequest):
            raise ContractError("request must be a LimitedRulePromotionRequest")
        if self.from_state != ProposalState.OWNER_REVIEW.value:
            raise ContractError("limited record from_state must be owner_review")
        _instant(self.approved_at, "approved_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "promotion_record_id": self.promotion_record_id,
            "request": self.request.to_dict(),
            "from_state": self.from_state,
            "owner_approval_id": self.owner_approval_id,
            "owner_principal_id": self.owner_principal_id,
            "approved_at": self.approved_at,
        }

    @property
    def record_digest(self) -> str:
        return content_hash(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LimitedRulePromotionRecord":
        if not isinstance(value, Mapping):
            raise ContractError("limited rule promotion record must be an object")
        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ContractError(
                "limited rule promotion record fields mismatch: "
                f"missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
        request = value["request"]
        if not isinstance(request, Mapping):
            raise ContractError("limited rule promotion request must be an object")
        return cls(
            promotion_record_id=value["promotion_record_id"],
            request=LimitedRulePromotionRequest.from_dict(request),
            from_state=value["from_state"],
            owner_approval_id=value["owner_approval_id"],
            owner_principal_id=value["owner_principal_id"],
            approved_at=value["approved_at"],
        )


@dataclass(frozen=True, slots=True)
class SealedCustodyAttestation:
    """Verifier-backed proof that sealed bytes/results were externally custodied."""

    attestation_id: str
    proof: str = field(repr=False)
    proposal_id: str
    eval_id: str
    project_id: str
    candidate_digest: str
    dataset_digest: str
    eval_attestation_digest: str
    evaluator_principal_id: str
    custody_provider: str
    custodian_id: str
    policy_version: str


class SealedCustodyVerifier(Protocol):
    authority_id: str

    def verify(self, attestation: SealedCustodyAttestation) -> object | None: ...


class DenyAllSealedCustodyVerifier:
    authority_id = "companyos.sealed-custody.deny-all.v1"

    def verify(self, attestation: SealedCustodyAttestation) -> None:
        del attestation
        raise AuthorizationError(
            "active promotion is disabled: no trusted external sealed-custody verifier configured"
        )


@dataclass(frozen=True, slots=True)
class ActiveRulePromotionRecord:
    """Canonical, append-only evidence snapshot for limited -> active promotion."""

    promotion_record_id: str
    candidate_id: str
    candidate_digest: str
    policy_version: str
    promotion_validation_eval_id: str
    promotion_validation_dataset_digest: str
    promotion_validation_attestation_digest: str
    promotion_validation_query_count: int
    promotion_validation_status: str
    limited_promotion_record_id: str
    limited_promotion_record_digest: str
    source_task_id: str
    verification_evidence_id: str
    verification_evidence_digest: str
    actual_outcome_kind: str
    actual_outcome: str
    from_state: str
    target_state: str
    proposal_maker_principal_id: str
    evaluator_principal_id: str
    evaluator_digest: str
    sealed_eval_id: str
    sealed_dataset_digest: str
    sealed_dataset_use_count: int
    sealed_result_influenced_edits: bool
    sealed_attestation_digest: str
    sealed_custody_attestation_id: str
    sealed_custody_provider: str
    sealed_custodian_id: str
    sealed_custody_attestation_digest: str
    sealed_custody_verified_at: str
    safety_hard_failures: int
    eval_status: str
    evaluated_at: str
    owner_approval_id: str
    owner_principal_id: str
    approved_at: str
    scope: str
    review_condition: str
    non_goals: tuple[str, ...]
    rollback_or_retirement_path: str
    non_claim_boundary: str

    def __post_init__(self) -> None:
        text_fields = (
            "promotion_record_id",
            "candidate_id",
            "policy_version",
            "promotion_validation_eval_id",
            "promotion_validation_status",
            "limited_promotion_record_id",
            "source_task_id",
            "verification_evidence_id",
            "actual_outcome_kind",
            "actual_outcome",
            "from_state",
            "target_state",
            "proposal_maker_principal_id",
            "evaluator_principal_id",
            "sealed_eval_id",
            "sealed_custody_attestation_id",
            "sealed_custody_provider",
            "sealed_custodian_id",
            "sealed_custody_verified_at",
            "eval_status",
            "owner_approval_id",
            "owner_principal_id",
            "scope",
            "review_condition",
            "rollback_or_retirement_path",
            "non_claim_boundary",
        )
        for name in text_fields:
            value = getattr(self, name)
            if _text(value, name) != value:
                raise ContractError(f"{name} must not contain surrounding whitespace")
        for name in (
            "candidate_digest",
            "promotion_validation_dataset_digest",
            "promotion_validation_attestation_digest",
            "limited_promotion_record_digest",
            "verification_evidence_digest",
            "evaluator_digest",
            "sealed_dataset_digest",
            "sealed_attestation_digest",
            "sealed_custody_attestation_digest",
        ):
            value = getattr(self, name)
            if _digest(value, name) != value:
                raise ContractError(f"{name} must be canonical")
        if (
            isinstance(self.promotion_validation_query_count, bool)
            or not isinstance(self.promotion_validation_query_count, int)
            or self.promotion_validation_query_count < 1
        ):
            raise ContractError(
                "promotion_validation_query_count must be a positive integer"
            )
        if self.promotion_validation_status != "pass":
            raise ContractError("promotion_validation_status must be pass")
        if self.from_state != ProposalState.LIMITED.value:
            raise ContractError("from_state must be limited")
        if self.target_state != ProposalState.ACTIVE.value:
            raise ContractError("target_state must be active")
        if (
            isinstance(self.sealed_dataset_use_count, bool)
            or self.sealed_dataset_use_count != 1
        ):
            raise ContractError("sealed_dataset_use_count must be exactly 1")
        if self.sealed_result_influenced_edits is not False:
            raise ContractError("sealed_result_influenced_edits must be false")
        if (
            isinstance(self.safety_hard_failures, bool)
            or self.safety_hard_failures != 0
        ):
            raise ContractError("safety_hard_failures must be exactly 0")
        if self.eval_status != "pass":
            raise ContractError("eval_status must be pass")
        if self.actual_outcome_kind not in _ACTUAL_OUTCOME_KINDS:
            raise ContractError("active record has an invalid actual_outcome_kind")
        if self.promotion_validation_dataset_digest == self.sealed_dataset_digest:
            raise ContractError(
                "promotion-validation and sealed datasets must be distinct"
            )
        if (
            len(
                {
                    self.proposal_maker_principal_id,
                    self.evaluator_principal_id,
                    self.owner_principal_id,
                    self.sealed_custodian_id,
                }
            )
            != 4
        ):
            raise ContractError(
                "proposal maker, evaluator, sealed custodian, and owner approver "
                "must be distinct"
            )
        evaluated = _instant(self.evaluated_at, "evaluated_at")
        custody_verified = _instant(
            self.sealed_custody_verified_at, "sealed_custody_verified_at"
        )
        approved = _instant(self.approved_at, "approved_at")
        if custody_verified < evaluated:
            raise ContractError(
                "sealed custody must be verified after the sealed evaluation"
            )
        if approved <= evaluated:
            raise ContractError("approved_at must be later than evaluated_at")
        if approved <= custody_verified:
            raise ContractError(
                "approved_at must be later than sealed_custody_verified_at"
            )
        if not isinstance(self.non_goals, tuple) or not self.non_goals:
            raise ContractError("non_goals must be a non-empty tuple")
        normalized_non_goals = tuple(_text(item, "non_goal") for item in self.non_goals)
        if normalized_non_goals != self.non_goals or len(set(self.non_goals)) != len(
            self.non_goals
        ):
            raise ContractError("non_goals must contain unique canonical strings")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["non_goals"] = list(self.non_goals)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActiveRulePromotionRecord":
        if not isinstance(value, Mapping):
            raise ContractError("active rule promotion record must be an object")
        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ContractError(
                "active rule promotion record fields mismatch: "
                f"missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
        values = dict(value)
        raw_non_goals = values["non_goals"]
        if not isinstance(raw_non_goals, list):
            raise ContractError("non_goals must be an array")
        values["non_goals"] = tuple(raw_non_goals)
        return cls(**values)


@dataclass(frozen=True)
class EvalRun:
    eval_id: str
    project_id: str
    candidate_digest: str
    dataset_name: str
    dataset_split: str
    dataset_digest: str
    evaluator: str
    evaluator_version: str
    status: str
    metrics: Mapping[str, float]
    safety_failures: tuple[str, ...]
    attestation_id: str
    attestation_digest: str
    created_at: str

    @property
    def clean_pass(self) -> bool:
        return self.status == "pass" and not self.safety_failures


@dataclass(frozen=True, slots=True)
class EvalResultAttestation:
    """Exact runner/custody proof envelope; proof bytes are never persisted."""

    attestation_id: str
    proof: str = field(repr=False)
    eval_id: str
    project_id: str
    candidate_digest: str
    dataset_name: str
    dataset_split: str
    dataset_digest: str
    evaluator_principal_id: str
    evaluator_version: str
    status: str
    metrics: Mapping[str, float]
    safety_failures: tuple[str, ...]
    policy_version: str


class EvalResultVerifier(Protocol):
    authority_id: str

    def verify(self, attestation: EvalResultAttestation) -> object | None: ...


class DenyAllEvalResultVerifier:
    authority_id = "companyos.eval-result.deny-all.v1"

    def verify(self, attestation: EvalResultAttestation) -> None:
        del attestation
        raise AuthorizationError(
            "evaluation recording is disabled: no trusted runner verifier configured"
        )


@dataclass(frozen=True)
class ImprovementProposal:
    proposal_id: str
    project_id: str
    source_run_id: str
    hypothesis: str
    candidate_digest: str
    editable_surface: str
    expected_benefit: str
    risk: str
    rollback_route: str
    held_in_eval_id: str | None
    held_out_eval_id: str | None
    sealed_eval_id: str | None
    state: ProposalState
    owner_approval_id: str | None
    created_at: str
    updated_at: str


def _eval(row: Mapping[str, Any]) -> EvalRun:
    return EvalRun(
        eval_id=row["eval_id"],
        project_id=row["project_id"],
        candidate_digest=row["candidate_digest"],
        dataset_name=row["dataset_name"],
        dataset_split=row["dataset_split"],
        dataset_digest=row["dataset_digest"],
        evaluator=row["evaluator"],
        evaluator_version=row["evaluator_version"],
        status=row["status"],
        metrics=json.loads(row["metrics_json"]),
        safety_failures=tuple(json.loads(row["safety_failures_json"])),
        attestation_id=row["attestation_id"],
        attestation_digest=row["attestation_digest"],
        created_at=row["created_at"],
    )


def _proposal(row: Mapping[str, Any]) -> ImprovementProposal:
    return ImprovementProposal(
        proposal_id=row["proposal_id"],
        project_id=row["project_id"],
        source_run_id=row["source_run_id"],
        hypothesis=row["hypothesis"],
        candidate_digest=row["candidate_digest"],
        editable_surface=row["editable_surface"],
        expected_benefit=row["expected_benefit"],
        risk=row["risk"],
        rollback_route=row["rollback_route"],
        held_in_eval_id=row["held_in_eval_id"],
        held_out_eval_id=row["held_out_eval_id"],
        sealed_eval_id=row["sealed_eval_id"],
        state=ProposalState(row["state"]),
        owner_approval_id=row["owner_approval_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class EvaluationRegistry:
    @property
    def store(self) -> SQLiteStore:
        return self.__store

    @property
    def policy_version(self) -> str:
        return self.__policy_version

    @property
    def identity(self) -> IdentityManager:
        return self.__identity

    @property
    def result_verifier(self) -> EvalResultVerifier:
        raise AttributeError("evaluation verifier implementation is private")

    @property
    def sealed_custody_verifier(self) -> SealedCustodyVerifier:
        raise AttributeError("sealed custody verifier implementation is private")

    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
        result_verifier: EvalResultVerifier | None = None,
        sealed_custody_verifier: SealedCustodyVerifier | None = None,
    ):
        self.__store = store
        self.__policy_version = policy_version
        self.__identity = identity or IdentityManager(store)
        self.__result_verifier = result_verifier or DenyAllEvalResultVerifier()
        self.__sealed_custody_verifier = (
            sealed_custody_verifier or DenyAllSealedCustodyVerifier()
        )
        self.__authority_config_digest = protected_authority_config_digest(
            "evaluation_registry",
            {
                "policy_version": policy_version,
                "result_verifier": _verifier_authority_id(self.__result_verifier),
                "sealed_custody_verifier": _verifier_authority_id(
                    self.__sealed_custody_verifier
                ),
            },
        )
        self.__command_authority = store._bind_protected_command_authority(
            self,
            "evaluation_registry",
            config_digest=self.__authority_config_digest,
            runtime_components=(
                self.__result_verifier,
                self.__sealed_custody_verifier,
            ),
        )

    def record_eval(
        self,
        *,
        project_id: str,
        candidate_digest: str,
        dataset_name: str,
        dataset_split: str,
        dataset_digest: str,
        evaluator: VerifiedPrincipal,
        evaluator_version: str,
        status: str,
        metrics: Mapping[str, Any],
        safety_failures: Iterable[str] = (),
        eval_id: str | None = None,
        attestation: EvalResultAttestation,
    ) -> EvalRun:
        project_id = _text(project_id, "project_id")
        candidate_digest = _digest(candidate_digest, "candidate_digest")
        dataset_name = _text(dataset_name, "dataset_name")
        dataset_split = _text(dataset_split, "dataset_split").lower()
        if dataset_split not in _SPLITS:
            raise ContractError("dataset_split must be held_in, held_out, or sealed")
        dataset_digest = _digest(dataset_digest, "dataset_digest")
        evaluator_id = self.identity.require_role(
            evaluator, Role.EVALUATOR
        ).principal_id
        evaluator_version = _text(evaluator_version, "evaluator_version")
        status = _text(status, "status").lower()
        if status not in _EVAL_STATUSES:
            raise ContractError(f"unsupported eval status: {status}")
        metric_values = _metrics(metrics)
        failures = tuple(_text(item, "safety_failure") for item in safety_failures)
        eval_id = _text(eval_id or str(uuid.uuid4()), "eval_id")
        if not isinstance(attestation, EvalResultAttestation):
            raise AuthorizationError("trusted evaluation attestation is required")
        expected_attestation = EvalResultAttestation(
            attestation_id=_text(attestation.attestation_id, "attestation_id"),
            proof=attestation.proof,
            eval_id=eval_id,
            project_id=project_id,
            candidate_digest=candidate_digest,
            dataset_name=dataset_name,
            dataset_split=dataset_split,
            dataset_digest=dataset_digest,
            evaluator_principal_id=evaluator_id,
            evaluator_version=evaluator_version,
            status=status,
            metrics=metric_values,
            safety_failures=failures,
            policy_version=self.policy_version,
        )
        if attestation != expected_attestation:
            raise AuthorizationError(
                "evaluation attestation does not exactly match the result"
            )
        verifier_result = self.__result_verifier.verify(attestation)
        if verifier_result is not None:
            raise AuthorizationError(
                "evaluation verifier must attest by returning None"
            )
        attestation_envelope = asdict(attestation)
        attestation_envelope.pop("proof")
        attestation_digest = content_hash(attestation_envelope)
        now = utc_now()
        with self.store.transaction(immediate=True) as connection:
            live_evaluator_id = self.identity.require_role_in_transaction(
                connection, evaluator, Role.EVALUATOR
            ).principal_id
            if live_evaluator_id != evaluator_id:
                raise AuthorizationError("evaluation bearer identity changed")
            existing = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (eval_id,)
            ).fetchone()
            if existing is not None:
                prior = _eval(existing)
                expected = (
                    project_id,
                    candidate_digest,
                    dataset_name,
                    dataset_split,
                    dataset_digest,
                    evaluator_id,
                    evaluator_version,
                    status,
                    metric_values,
                    failures,
                    attestation.attestation_id,
                    attestation_digest,
                )
                actual = (
                    prior.project_id,
                    prior.candidate_digest,
                    prior.dataset_name,
                    prior.dataset_split,
                    prior.dataset_digest,
                    prior.evaluator,
                    prior.evaluator_version,
                    prior.status,
                    dict(prior.metrics),
                    prior.safety_failures,
                    prior.attestation_id,
                    prior.attestation_digest,
                )
                if actual != expected:
                    raise ContractError(
                        f"eval id reused with different result: {eval_id}"
                    )
                return prior
            if dataset_split == "sealed":
                reused = connection.execute(
                    "SELECT eval_id FROM eval_runs WHERE dataset_split = 'sealed' "
                    "AND dataset_digest = ? LIMIT 1",
                    (dataset_digest,),
                ).fetchone()
                if reused is not None:
                    raise AuthorizationError(
                        "sealed dataset is burned and cannot be reused after one eval"
                    )
            payload = {
                "candidate_digest": candidate_digest,
                "dataset_name": dataset_name,
                "dataset_split": dataset_split,
                "dataset_digest": dataset_digest,
                "evaluator": evaluator_id,
                "evaluator_version": evaluator_version,
                "status": status,
                "metrics": metric_values,
                "safety_failures": list(failures),
                "attestation_id": attestation.attestation_id,
                "attestation_digest": attestation_digest,
                # The proposal digest is immutable in this runtime. A sealed
                # result cannot mutate the candidate through any registry API;
                # external edit/custody activity remains outside this claim.
                "result_influenced_edits": False,
            }
            self.store.append_event(
                connection,
                aggregate_type="eval",
                aggregate_id=eval_id,
                expected_version=0,
                project_id=project_id,
                event_type="eval_recorded",
                actor=evaluator_id,
                command_id=str(uuid.uuid4()),
                correlation_id=eval_id,
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                command_owner=self,
            )
            connection.execute(
                """
                INSERT INTO eval_runs(
                    eval_id, project_id, candidate_digest, dataset_name,
                    dataset_split, dataset_digest, evaluator,
                    evaluator_version, status, metrics_json,
                    safety_failures_json, attestation_id, attestation_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eval_id,
                    project_id,
                    candidate_digest,
                    dataset_name,
                    dataset_split,
                    dataset_digest,
                    evaluator_id,
                    evaluator_version,
                    status,
                    canonical_json(metric_values),
                    canonical_json(list(failures)),
                    attestation.attestation_id,
                    attestation_digest,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (eval_id,)
            ).fetchone()
            return _eval(row)

    def propose(
        self,
        *,
        project_id: str,
        source_run_id: str,
        hypothesis: str,
        candidate_digest: str,
        editable_surface: str,
        expected_benefit: str,
        risk: str,
        rollback_route: str,
        proposer: VerifiedPrincipal,
        proposal_id: str | None = None,
    ) -> ImprovementProposal:
        project_id = _text(project_id, "project_id")
        source_run_id = _text(source_run_id, "source_run_id")
        hypothesis = _text(hypothesis, "hypothesis")
        candidate_digest = _digest(candidate_digest, "candidate_digest")
        editable_surface = _text(editable_surface, "editable_surface")
        if (
            editable_surface in _PROTECTED_SURFACES
            or editable_surface not in _EDITABLE_SURFACES
        ):
            raise AuthorizationError(
                f"self-improvement surface is not editable: {editable_surface}"
            )
        expected_benefit = _text(expected_benefit, "expected_benefit")
        risk = _text(risk, "risk")
        rollback_route = _text(rollback_route, "rollback_route")
        proposal_id = _text(proposal_id or str(uuid.uuid4()), "proposal_id")
        now = utc_now()
        with self.store.transaction(immediate=True) as connection:
            proposer_record = self.identity.verify_in_transaction(connection, proposer)
            if not proposer_record.roles.intersection({Role.WORKER, Role.SYSTEM}):
                raise AuthorizationError(
                    "improvement proposer requires worker or system role"
                )
            proposer_id = proposer_record.principal_id
            run = connection.execute(
                "SELECT project_id FROM runs WHERE run_id = ?", (source_run_id,)
            ).fetchone()
            if run is None or run["project_id"] != project_id:
                raise NotFoundError(f"source run not found in project: {source_run_id}")
            payload = {
                "hypothesis": hypothesis,
                "candidate_digest": candidate_digest,
                "editable_surface": editable_surface,
                "expected_benefit": expected_benefit,
                "risk": risk,
                "rollback_route": rollback_route,
            }
            self.store.append_event(
                connection,
                aggregate_type="improvement",
                aggregate_id=proposal_id,
                expected_version=0,
                project_id=project_id,
                run_id=source_run_id,
                event_type="improvement_proposed",
                actor=proposer_id,
                command_id=str(uuid.uuid4()),
                correlation_id=source_run_id,
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                command_owner=self,
            )
            connection.execute(
                """
                INSERT INTO improvement_proposals(
                    proposal_id, project_id, source_run_id, hypothesis,
                    candidate_digest, editable_surface, expected_benefit,
                    risk, rollback_route, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal_id,
                    project_id,
                    source_run_id,
                    hypothesis,
                    candidate_digest,
                    editable_surface,
                    expected_benefit,
                    risk,
                    rollback_route,
                    ProposalState.CANDIDATE.value,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            return _proposal(row)

    def attach_eval(
        self,
        proposal_id: str,
        eval_id: str,
        *,
        actor: VerifiedPrincipal,
    ) -> ImprovementProposal:
        proposal_id = _text(proposal_id, "proposal_id")
        eval_id = _text(eval_id, "eval_id")
        with self.store.transaction(immediate=True) as connection:
            actor_id = self.identity.require_role_in_transaction(
                connection, actor, Role.SYSTEM
            ).principal_id
            row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            evaluation_row = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (eval_id,)
            ).fetchone()
            if evaluation_row is None:
                raise NotFoundError(f"eval not found: {eval_id}")
            evaluation = _eval(evaluation_row)
            proposer = connection.execute(
                "SELECT actor FROM events WHERE aggregate_type = 'improvement' "
                "AND aggregate_id = ? AND event_type = 'improvement_proposed'",
                (proposal_id,),
            ).fetchone()
            if proposer is None or proposer["actor"] == evaluation.evaluator:
                raise AuthorizationError(
                    "proposal maker and evaluator must be independent"
                )
            if (
                evaluation.project_id != row["project_id"]
                or evaluation.candidate_digest != row["candidate_digest"]
            ):
                raise ContractError(
                    "evaluation does not match proposal project/candidate digest"
                )
            if not evaluation.clean_pass:
                target_state = ProposalState.REJECTED
            elif evaluation.dataset_split == "held_in":
                if row["held_in_eval_id"] is not None:
                    raise TransitionError("held-in evaluation is already attached")
                target_state = ProposalState.HELDOUT_PENDING
            elif evaluation.dataset_split == "held_out":
                if (
                    row["state"] != ProposalState.HELDOUT_PENDING.value
                    or row["held_in_eval_id"] is None
                ):
                    raise TransitionError(
                        "a clean held-in evaluation must precede held-out evaluation"
                    )
                held_in = connection.execute(
                    "SELECT dataset_digest FROM eval_runs WHERE eval_id = ?",
                    (row["held_in_eval_id"],),
                ).fetchone()
                if held_in["dataset_digest"] == evaluation.dataset_digest:
                    raise ContractError(
                        "held-out dataset must be isolated from held-in data"
                    )
                target_state = ProposalState.OWNER_REVIEW
            else:
                if (
                    row["state"] != ProposalState.LIMITED.value
                    or row["held_out_eval_id"] is None
                ):
                    raise TransitionError(
                        "sealed evaluation is allowed only after limited promotion"
                    )
                if row["sealed_eval_id"] is not None:
                    raise TransitionError("sealed evaluation is already attached")
                limited_events = connection.execute(
                    "SELECT payload_json, recorded_at FROM events "
                    "WHERE aggregate_type = 'improvement' AND aggregate_id = ? "
                    "AND event_type = 'improvement_promoted' ORDER BY seq",
                    (proposal_id,),
                ).fetchall()
                limited_at = next(
                    (
                        item["recorded_at"]
                        for item in reversed(limited_events)
                        if json.loads(item["payload_json"]).get("to")
                        == ProposalState.LIMITED.value
                    ),
                    None,
                )
                if limited_at is None or evaluation.created_at <= limited_at:
                    raise TransitionError(
                        "sealed evaluation must be recorded after limited promotion"
                    )
                prior_digests = {
                    item["dataset_digest"]
                    for item in connection.execute(
                        "SELECT dataset_digest FROM eval_runs WHERE eval_id IN (?, ?)",
                        (row["held_in_eval_id"], row["held_out_eval_id"]),
                    ).fetchall()
                }
                if evaluation.dataset_digest in prior_digests:
                    raise ContractError(
                        "sealed dataset must be isolated from discovery and promotion validation"
                    )
                target_state = ProposalState.LIMITED
            version = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
                "WHERE aggregate_type = 'improvement' AND aggregate_id = ?",
                (proposal_id,),
            ).fetchone()[0]
            self.store.append_event(
                connection,
                aggregate_type="improvement",
                aggregate_id=proposal_id,
                expected_version=int(version),
                project_id=row["project_id"],
                run_id=row["source_run_id"],
                event_type="improvement_eval_attached",
                actor=actor_id,
                command_id=str(uuid.uuid4()),
                correlation_id=row["source_run_id"],
                policy_version=self.policy_version,
                payload={
                    "eval_id": eval_id,
                    "dataset_split": evaluation.dataset_split,
                    "clean_pass": evaluation.clean_pass,
                    "state": target_state.value,
                },
                command_authority=self.__command_authority,
                command_owner=self,
            )
            column = {
                "held_in": "held_in_eval_id",
                "held_out": "held_out_eval_id",
                "sealed": "sealed_eval_id",
            }[evaluation.dataset_split]
            connection.execute(
                f"UPDATE improvement_proposals SET {column} = ?, state = ?, updated_at = ? "
                "WHERE proposal_id = ?",
                (eval_id, target_state.value, utc_now(), proposal_id),
            )
            updated = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            return _proposal(updated)

    def _verified_limited_source_evidence(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        source_task_id: str,
        verification_evidence_id: str,
        before_seq: int | None,
    ) -> tuple[Any, str, int]:
        """Verify one delivered source Run/Task and its accepted PASS claim."""

        task = connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (source_task_id,)
        ).fetchone()
        run = connection.execute(
            "SELECT * FROM runs WHERE run_id = ?", (proposal_row["source_run_id"],)
        ).fetchone()
        if (
            run is None
            or task is None
            or run["project_id"] != proposal_row["project_id"]
            or task["project_id"] != proposal_row["project_id"]
            or task["run_id"] != proposal_row["source_run_id"]
            or task["goal_id"] != run["goal_id"]
            or LoopState(run["loop_state"]) is not LoopState.DELIVERED
            or TaskState(task["state"]) is not TaskState.DELIVERED
        ):
            raise TransitionError(
                "limited promotion requires a delivered source Run and Task in the proposal project"
            )
        spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
        evidence = connection.execute(
            "SELECT * FROM evidence_claims WHERE evidence_id = ? AND task_id = ?",
            (verification_evidence_id, source_task_id),
        ).fetchone()
        if (
            evidence is None
            or evidence["project_id"] != proposal_row["project_id"]
            or evidence["run_id"] != proposal_row["source_run_id"]
            or evidence["evidence_state"] != spec.evidence_target.value
            or evidence["evidence_state"] not in _VERIFICATION_STATES
            or evidence["evaluator_verdict"] not in _PASSING_EVALUATOR_VERDICTS
        ):
            raise TransitionError(
                "limited promotion requires the source Task's passing verification evidence"
            )
        try:
            artifact_refs = json.loads(evidence["artifact_refs_json"])
            non_claims = json.loads(evidence["non_claims_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(
                "limited source evidence projection is invalid"
            ) from exc
        if (
            not isinstance(artifact_refs, list)
            or not artifact_refs
            or not all(isinstance(item, str) and item for item in artifact_refs)
            or not isinstance(non_claims, list)
        ):
            raise IntegrityError("limited source evidence projection is invalid")
        placeholders = ",".join("?" for _ in artifact_refs)
        artifacts = connection.execute(
            f"SELECT * FROM artifacts "
            f"WHERE artifact_id IN ({placeholders}) ORDER BY artifact_id",
            tuple(artifact_refs),
        ).fetchall()
        if len(artifacts) != len(set(artifact_refs)) or any(
            item["task_id"] != source_task_id for item in artifacts
        ):
            raise IntegrityError("limited source evidence artifacts are invalid")

        evidence_authority_digest = protected_authority_config_digest(
            "evidence_registry", {"policy_version": self.policy_version}
        )
        artifact_envelopes: list[dict[str, Any]] = []
        for artifact in artifacts:
            artifact_events = connection.execute(
                "SELECT * FROM events WHERE aggregate_type = 'artifact' "
                "AND aggregate_id = ? AND event_type = 'artifact_registered'",
                (artifact["artifact_id"],),
            ).fetchall()
            if len(artifact_events) != 1:
                raise IntegrityError(
                    "limited source artifact authority event is not unique"
                )
            artifact_event = artifact_events[0]
            try:
                artifact_payload = json.loads(artifact_event["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError(
                    "limited source artifact event is invalid"
                ) from exc
            expected_artifact_payload = {
                "kind": artifact["kind"],
                "uri": artifact["uri"],
                "content_digest": artifact["content_digest"],
                "confidentiality": artifact["confidentiality"],
                "producer_principal_id": artifact["producer_principal_id"],
            }
            self.store._verify_protected_event_authority(
                artifact_event,
                expected_handler="evidence_registry",
                expected_config_digest=evidence_authority_digest,
            )
            if (
                artifact_payload != expected_artifact_payload
                or artifact_event["aggregate_version"] != 1
                or artifact_event["project_id"] != proposal_row["project_id"]
                or artifact_event["run_id"] != proposal_row["source_run_id"]
                or artifact_event["task_id"] != source_task_id
                or artifact_event["actor"] != artifact["producer_principal_id"]
                or artifact_event["correlation_id"] != proposal_row["source_run_id"]
                or artifact_event["policy_version"] != self.policy_version
                or artifact_event["confidentiality"] != artifact["confidentiality"]
                or _instant(artifact["created_at"], "artifact.created_at")
                > _instant(artifact_event["occurred_at"], "artifact event occurred_at")
            ):
                raise IntegrityError(
                    "limited source artifact projection/event mismatch"
                )
            artifact_envelopes.append(
                {
                    **expected_artifact_payload,
                    "artifact_id": artifact["artifact_id"],
                    "event_seq": int(artifact_event["seq"]),
                }
            )

        evidence_events = connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'evidence' "
            "AND aggregate_id = ? AND event_type = 'evidence_claim_recorded'",
            (verification_evidence_id,),
        ).fetchall()
        if len(evidence_events) != 1:
            raise IntegrityError(
                "limited source evidence authority event is not unique"
            )
        evidence_event = evidence_events[0]
        try:
            evidence_payload = json.loads(evidence_event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("limited source evidence event is invalid") from exc
        expected_evidence_payload = {
            "claim": evidence["claim"],
            "evidence_state": evidence["evidence_state"],
            "artifact_refs": artifact_refs,
            "verifier_principal_id": evidence["verifier_principal_id"],
            "verifier_version": evidence["verifier_version"],
            "environment": evidence["environment"],
            "evaluator_verdict": evidence["evaluator_verdict"],
            "non_claims": non_claims,
        }
        self.store._verify_protected_event_authority(
            evidence_event,
            expected_handler="evidence_registry",
            expected_config_digest=evidence_authority_digest,
        )
        if (
            evidence_payload != expected_evidence_payload
            or evidence_event["aggregate_version"] != 1
            or evidence_event["project_id"] != proposal_row["project_id"]
            or evidence_event["run_id"] != proposal_row["source_run_id"]
            or evidence_event["task_id"] != source_task_id
            or evidence_event["actor"] != evidence["verifier_principal_id"]
            or evidence_event["correlation_id"] != proposal_row["source_run_id"]
            or evidence_event["policy_version"] != self.policy_version
        ):
            raise IntegrityError("limited source evidence projection/event mismatch")
        try:
            provenance = classify_promotion_provenance(
                environment=evidence["environment"], artifacts=artifacts
            )
        except EvidenceError as exc:
            raise TransitionError(
                "limited promotion source provenance is malformed or non-real"
            ) from exc
        if not provenance.real_task_eligible:
            raise TransitionError(
                "limited promotion requires real-task evidence provenance: "
                f"{list(provenance.rejection_reasons)}"
            )

        task_events = connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'task' AND aggregate_id = ? "
            "AND event_type = 'task_state_changed' ORDER BY seq",
            (source_task_id,),
        ).fetchall()
        accepted: list[tuple[Any, dict[str, Any]]] = []
        delivered: list[tuple[Any, dict[str, Any]]] = []
        for event in task_events:
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("limited source Task event is invalid") from exc
            if payload.get("accepted_evidence_id") == verification_evidence_id:
                accepted.append((event, payload))
            if payload.get("target") == TaskState.DELIVERED.value:
                delivered.append((event, payload))
        run_events = connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'run' AND aggregate_id = ? "
            "AND event_type = ? ORDER BY seq",
            (proposal_row["source_run_id"], "delivery_confirmed"),
        ).fetchall()
        if len(accepted) != 1 or len(delivered) != 1 or len(run_events) != 1:
            raise IntegrityError(
                "limited source evidence must be accepted before exact Task/Run delivery"
            )
        accepted_event, accepted_payload = accepted[0]
        if (
            set(accepted_payload)
            != {"from", "target", "reason", "accepted_evidence_id"}
            or accepted_payload["accepted_evidence_id"] != verification_evidence_id
            or accepted_payload["from"]
            not in {
                TaskState.EVIDENCE_PENDING.value,
                TaskState.EVALUATOR_PENDING.value,
            }
            or accepted_payload["target"]
            not in {
                TaskState.EVALUATOR_PENDING.value,
                TaskState.INTEGRATION_PENDING.value,
            }
            or not isinstance(accepted_payload["reason"], str)
            or not accepted_payload["reason"].strip()
        ):
            raise IntegrityError(
                "limited source evidence acceptance linkage is invalid"
            )
        delivered_event, delivered_payload = delivered[0]
        run_delivered_event = run_events[0]
        try:
            run_delivered_payload = json.loads(run_delivered_event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(
                "limited source Run delivery event is invalid"
            ) from exc
        if not isinstance(run_delivered_payload, dict):
            raise IntegrityError("limited source Run delivery event is invalid")
        run_guards = run_delivered_payload.get("guards")
        upper_bound = before_seq if before_seq is not None else 2**63 - 1
        if (
            accepted_event["project_id"] != proposal_row["project_id"]
            or accepted_event["run_id"] != proposal_row["source_run_id"]
            or accepted_event["task_id"] != source_task_id
            or accepted_event["correlation_id"] != proposal_row["source_run_id"]
            or accepted_event["policy_version"] != self.policy_version
            or set(delivered_payload) != {"from", "target", "reason"}
            or delivered_payload["from"] != TaskState.INTEGRATION_PENDING.value
            or delivered_payload["target"] != TaskState.DELIVERED.value
            or delivered_event["project_id"] != proposal_row["project_id"]
            or delivered_event["run_id"] != proposal_row["source_run_id"]
            or delivered_event["task_id"] != source_task_id
            or delivered_event["correlation_id"] != proposal_row["source_run_id"]
            or delivered_event["policy_version"] != self.policy_version
            or run_delivered_payload.get("event") != "delivery_confirmed"
            or run_delivered_payload.get("payload") != {}
            or not isinstance(run_guards, dict)
            or not run_guards
            or not all(value is True for value in run_guards.values())
            or run_delivered_event["project_id"] != proposal_row["project_id"]
            or run_delivered_event["run_id"] != proposal_row["source_run_id"]
            or run_delivered_event["task_id"] is not None
            or run_delivered_event["correlation_id"] != proposal_row["source_run_id"]
            or run_delivered_event["policy_version"] != self.policy_version
            or any(
                item["event_seq"] >= int(evidence_event["seq"])
                for item in artifact_envelopes
            )
            or not (
                int(evidence_event["seq"])
                < int(accepted_event["seq"])
                < int(delivered_event["seq"])
                < int(run_delivered_event["seq"])
                < upper_bound
            )
        ):
            raise IntegrityError(
                "limited source evidence acceptance/delivery order is invalid"
            )
        evidence_envelope = {
            **expected_evidence_payload,
            "evidence_id": verification_evidence_id,
            "project_id": evidence["project_id"],
            "run_id": evidence["run_id"],
            "task_id": evidence["task_id"],
            "artifacts": artifact_envelopes,
            "evidence_event_seq": int(evidence_event["seq"]),
            "acceptance_event_seq": int(accepted_event["seq"]),
            "task_delivery_event_seq": int(delivered_event["seq"]),
            "run_delivery_event_seq": int(run_delivered_event["seq"]),
        }
        return (
            evidence,
            content_hash(evidence_envelope),
            int(run_delivered_event["seq"]),
        )

    def _build_limited_request(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        source_task_id: str,
        verification_evidence_id: str,
        scope: str,
        actual_outcome_kind: str,
        actual_outcome: str,
        non_goals: Iterable[str],
        review_condition: str,
        rollback_or_retirement_path: str,
        non_claim_boundary: str,
        before_seq: int | None,
    ) -> LimitedRulePromotionRequest:
        if proposal_row["state"] not in {
            ProposalState.OWNER_REVIEW.value,
            ProposalState.LIMITED.value,
            ProposalState.ACTIVE.value,
        }:
            raise TransitionError(
                "proposal must have completed promotion-validation before limited review"
            )
        heldout_row = connection.execute(
            "SELECT * FROM eval_runs WHERE eval_id = ?",
            (proposal_row["held_out_eval_id"],),
        ).fetchone()
        if heldout_row is None:
            raise TransitionError("clean promotion-validation evaluation is required")
        heldout = _eval(heldout_row)
        if (
            not heldout.clean_pass
            or heldout.dataset_split != "held_out"
            or heldout.project_id != proposal_row["project_id"]
            or heldout.candidate_digest != proposal_row["candidate_digest"]
        ):
            raise TransitionError("clean promotion-validation evaluation is required")
        heldout_event, _ = self._verified_eval_event(connection, heldout)
        self._verified_eval_attachment_event(
            connection,
            proposal_row=proposal_row,
            evaluation=heldout,
            evaluation_event=heldout_event,
            before_seq=before_seq,
        )
        evidence, evidence_digest, _ = self._verified_limited_source_evidence(
            connection,
            proposal_row=proposal_row,
            source_task_id=_text(source_task_id, "source_task_id"),
            verification_evidence_id=_text(
                verification_evidence_id, "verification_evidence_id"
            ),
            before_seq=before_seq,
        )
        outcome = _text(actual_outcome, "actual_outcome")
        if outcome != evidence["claim"]:
            raise ContractError(
                "actual_outcome must exactly equal the accepted verification evidence claim"
            )
        rollback = _text(rollback_or_retirement_path, "rollback_or_retirement_path")
        if rollback != proposal_row["rollback_route"]:
            raise ContractError(
                "limited rollback path must match the frozen proposal rollback route"
            )
        return LimitedRulePromotionRequest(
            candidate_id=proposal_row["proposal_id"],
            candidate_digest=proposal_row["candidate_digest"],
            policy_version=self.policy_version,
            target_state=ProposalState.LIMITED.value,
            source_run_id=proposal_row["source_run_id"],
            source_task_id=source_task_id,
            verification_evidence_id=verification_evidence_id,
            verification_evidence_digest=evidence_digest,
            verification_evidence_state=evidence["evidence_state"],
            verification_evaluator_verdict=evidence["evaluator_verdict"],
            promotion_validation_eval_id=heldout.eval_id,
            promotion_validation_dataset_digest=heldout.dataset_digest,
            promotion_validation_attestation_digest=heldout.attestation_digest,
            promotion_validation_query_count=self._eval_dataset_use_count(
                connection,
                dataset_split="held_out",
                dataset_digest=heldout.dataset_digest,
                before_seq=before_seq,
            ),
            promotion_validation_status=heldout.status,
            scope=_bounded_scope(scope, proposal_row["project_id"]),
            actual_outcome_kind=_text(
                actual_outcome_kind, "actual_outcome_kind"
            ).lower(),
            actual_outcome=outcome,
            risk=proposal_row["risk"],
            non_goals=_strings(non_goals, "non_goal"),
            review_condition=_text(review_condition, "review_condition"),
            rollback_or_retirement_path=rollback,
            non_claim_boundary=_text(non_claim_boundary, "non_claim_boundary"),
        )

    def build_limited_promotion_request(
        self,
        proposal_id: str,
        *,
        source_task_id: str,
        verification_evidence_id: str,
        scope: str,
        actual_outcome_kind: str,
        actual_outcome: str,
        non_goals: Iterable[str],
        review_condition: str,
        rollback_or_retirement_path: str,
        non_claim_boundary: str,
    ) -> LimitedRulePromotionRequest:
        """Build the exact request digest an Owner must approve for LIMITED."""

        proposal_id = _text(proposal_id, "proposal_id")
        with self.store.transaction() as connection:
            self.store.verify_event_chain(connection)
            proposal_row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if proposal_row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            if proposal_row["state"] != ProposalState.OWNER_REVIEW.value:
                raise TransitionError(
                    "proposal must be owner_review before a limited request is built"
                )
            self._verified_proposal_event(connection, proposal_row)
            return self._build_limited_request(
                connection,
                proposal_row=proposal_row,
                source_task_id=source_task_id,
                verification_evidence_id=verification_evidence_id,
                scope=scope,
                actual_outcome_kind=actual_outcome_kind,
                actual_outcome=actual_outcome,
                non_goals=non_goals,
                review_condition=review_condition,
                rollback_or_retirement_path=rollback_or_retirement_path,
                non_claim_boundary=non_claim_boundary,
                before_seq=None,
            )

    def record_sealed_custody_attestation(
        self,
        proposal_id: str,
        *,
        attestation: SealedCustodyAttestation,
    ) -> str:
        """Persist a verifier-accepted external custody envelope; proof stays out."""

        proposal_id = _text(proposal_id, "proposal_id")
        if not isinstance(attestation, SealedCustodyAttestation):
            raise AuthorizationError("sealed custody attestation is required")
        with self.store.transaction(immediate=True) as connection:
            self.store.verify_event_chain(connection)
            proposal_row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if proposal_row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            if proposal_row["state"] != ProposalState.LIMITED.value:
                raise TransitionError(
                    "sealed custody may be attested only for a limited proposal"
                )
            sealed_row = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?",
                (proposal_row["sealed_eval_id"],),
            ).fetchone()
            if sealed_row is None:
                raise TransitionError("a sealed evaluation must be attached first")
            sealed = _eval(sealed_row)
            expected = SealedCustodyAttestation(
                attestation_id=_text(attestation.attestation_id, "attestation_id"),
                proof=attestation.proof,
                proposal_id=proposal_id,
                eval_id=sealed.eval_id,
                project_id=proposal_row["project_id"],
                candidate_digest=proposal_row["candidate_digest"],
                dataset_digest=sealed.dataset_digest,
                eval_attestation_digest=sealed.attestation_digest,
                evaluator_principal_id=sealed.evaluator,
                custody_provider=_text(
                    attestation.custody_provider, "custody_provider"
                ),
                custodian_id=_text(attestation.custodian_id, "custodian_id"),
                policy_version=self.policy_version,
            )
            if attestation != expected:
                raise AuthorizationError(
                    "sealed custody attestation does not exactly match the frozen evaluation"
                )
            if attestation.custodian_id == sealed.evaluator:
                raise AuthorizationError(
                    "sealed custodian and evaluator must be distinct"
                )
            verifier_result = self.__sealed_custody_verifier.verify(attestation)
            if verifier_result is not None:
                raise AuthorizationError(
                    "sealed custody verifier must attest by returning None"
                )
            self._verified_proposal_event(connection, proposal_row)
            sealed_event, _ = self._verified_eval_event(connection, sealed)
            self._verified_eval_attachment_event(
                connection,
                proposal_row=proposal_row,
                evaluation=sealed,
                evaluation_event=sealed_event,
                before_seq=None,
            )
            envelope = asdict(attestation)
            envelope.pop("proof")
            attestation_digest = content_hash(envelope)
            existing = connection.execute(
                "SELECT * FROM sealed_custody_attestations WHERE attestation_id = ?",
                (attestation.attestation_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["proposal_id"] == proposal_id
                    and existing["eval_id"] == sealed.eval_id
                    and existing["attestation_digest"] == attestation_digest
                ):
                    self._verified_sealed_custody(
                        connection,
                        proposal_row=proposal_row,
                        sealed=sealed,
                        sealed_event=sealed_event,
                        before_seq=None,
                    )
                    return attestation_digest
                raise ContractError(
                    "sealed custody attestation id reused with different authority"
                )
            now = utc_now()
            payload = {
                **envelope,
                "attestation_digest": attestation_digest,
                "verified_at": now,
            }
            self.store.append_event(
                connection,
                aggregate_type="sealed_custody",
                aggregate_id=attestation.attestation_id,
                expected_version=0,
                project_id=proposal_row["project_id"],
                run_id=proposal_row["source_run_id"],
                event_type="sealed_custody_attested",
                actor=attestation.custodian_id,
                command_id=str(uuid.uuid4()),
                correlation_id=proposal_row["source_run_id"],
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                command_owner=self,
            )
            connection.execute(
                """
                INSERT INTO sealed_custody_attestations(
                    attestation_id, proposal_id, eval_id, project_id,
                    candidate_digest, dataset_digest, eval_attestation_digest,
                    evaluator_principal_id, custody_provider, custodian_id, policy_version,
                    attestation_digest, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attestation.attestation_id,
                    proposal_id,
                    sealed.eval_id,
                    proposal_row["project_id"],
                    proposal_row["candidate_digest"],
                    sealed.dataset_digest,
                    sealed.attestation_digest,
                    sealed.evaluator,
                    attestation.custody_provider,
                    attestation.custodian_id,
                    self.policy_version,
                    attestation_digest,
                    now,
                ),
            )
            return attestation_digest

    def _verified_eval_event(
        self, connection: Any, evaluation: EvalRun
    ) -> tuple[Any, dict[str, Any]]:
        events = connection.execute(
            """
            SELECT * FROM events
            WHERE aggregate_type = 'eval' AND aggregate_id = ?
              AND event_type = 'eval_recorded'
            """,
            (evaluation.eval_id,),
        ).fetchall()
        if not events:
            raise IntegrityError(
                f"evaluation has no append-only source event: {evaluation.eval_id}"
            )
        if len(events) != 1:
            raise IntegrityError(
                f"evaluation has multiple source events: {evaluation.eval_id}"
            )
        event = events[0]
        try:
            payload = json.loads(event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(
                f"evaluation event payload is invalid: {evaluation.eval_id}"
            ) from exc
        expected = {
            "candidate_digest": evaluation.candidate_digest,
            "dataset_name": evaluation.dataset_name,
            "dataset_split": evaluation.dataset_split,
            "dataset_digest": evaluation.dataset_digest,
            "evaluator": evaluation.evaluator,
            "evaluator_version": evaluation.evaluator_version,
            "status": evaluation.status,
            "metrics": dict(evaluation.metrics),
            "safety_failures": list(evaluation.safety_failures),
            "attestation_id": evaluation.attestation_id,
            "attestation_digest": evaluation.attestation_digest,
            "result_influenced_edits": False,
        }
        self.store._verify_protected_event_authority(
            event,
            expected_handler="evaluation_registry",
            expected_config_digest=self.__authority_config_digest,
        )
        if (
            not isinstance(payload, dict)
            or payload != expected
            or event["project_id"] != evaluation.project_id
            or event["aggregate_version"] != 1
            or event["run_id"] is not None
            or event["task_id"] is not None
            or event["actor"] != evaluation.evaluator
            or event["correlation_id"] != evaluation.eval_id
            or event["policy_version"] != self.policy_version
            or _instant(evaluation.created_at, "evaluation.created_at")
            > _instant(event["occurred_at"], "evaluation event occurred_at")
        ):
            raise IntegrityError(
                f"evaluation projection/event mismatch: {evaluation.eval_id}"
            )
        return event, payload

    def _verified_eval_attachment_event(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        evaluation: EvalRun,
        evaluation_event: Any,
        before_seq: int | None,
    ) -> Any:
        matches: list[tuple[Any, dict[str, Any]]] = []
        for event in connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'improvement' "
            "AND aggregate_id = ? AND event_type = 'improvement_eval_attached' "
            "ORDER BY seq",
            (proposal_row["proposal_id"],),
        ).fetchall():
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("evaluation attachment event is invalid") from exc
            if (
                isinstance(payload, dict)
                and payload.get("eval_id") == evaluation.eval_id
            ):
                matches.append((event, payload))
        if len(matches) != 1:
            raise IntegrityError("evaluation attachment authority event is not unique")
        event, payload = matches[0]
        target_state = {
            "held_in": ProposalState.HELDOUT_PENDING.value,
            "held_out": ProposalState.OWNER_REVIEW.value,
            "sealed": ProposalState.LIMITED.value,
        }[evaluation.dataset_split]
        expected_payload = {
            "eval_id": evaluation.eval_id,
            "dataset_split": evaluation.dataset_split,
            "clean_pass": evaluation.clean_pass,
            "state": target_state,
        }
        self.store._verify_protected_event_authority(
            event,
            expected_handler="evaluation_registry",
            expected_config_digest=self.__authority_config_digest,
        )
        upper_bound = before_seq if before_seq is not None else 2**63 - 1
        if (
            payload != expected_payload
            or event["project_id"] != proposal_row["project_id"]
            or event["run_id"] != proposal_row["source_run_id"]
            or event["task_id"] is not None
            or event["correlation_id"] != proposal_row["source_run_id"]
            or event["policy_version"] != self.policy_version
            or not int(evaluation_event["seq"]) < int(event["seq"]) < upper_bound
        ):
            raise IntegrityError("evaluation attachment projection/event mismatch")
        return event

    def _verified_proposal_event(
        self, connection: Any, proposal_row: Any
    ) -> tuple[Any, dict[str, Any]]:
        events = connection.execute(
            """
            SELECT * FROM events
            WHERE aggregate_type = 'improvement' AND aggregate_id = ?
              AND event_type = 'improvement_proposed'
            """,
            (proposal_row["proposal_id"],),
        ).fetchall()
        if not events:
            raise IntegrityError("active promotion has no proposal-maker event")
        if len(events) != 1:
            raise IntegrityError("proposal has multiple proposal-maker events")
        event = events[0]
        try:
            payload = json.loads(event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("proposal-maker event payload is invalid") from exc
        expected = {
            "hypothesis": proposal_row["hypothesis"],
            "candidate_digest": proposal_row["candidate_digest"],
            "editable_surface": proposal_row["editable_surface"],
            "expected_benefit": proposal_row["expected_benefit"],
            "risk": proposal_row["risk"],
            "rollback_route": proposal_row["rollback_route"],
        }
        self.store._verify_protected_event_authority(
            event,
            expected_handler="evaluation_registry",
            expected_config_digest=self.__authority_config_digest,
        )
        if (
            not isinstance(payload, dict)
            or payload != expected
            or event["aggregate_version"] != 1
            or event["project_id"] != proposal_row["project_id"]
            or event["run_id"] != proposal_row["source_run_id"]
            or event["task_id"] is not None
            or event["correlation_id"] != proposal_row["source_run_id"]
            or event["policy_version"] != self.policy_version
            or _instant(proposal_row["created_at"], "proposal.created_at")
            > _instant(event["occurred_at"], "proposal event occurred_at")
        ):
            raise IntegrityError("proposal projection/event mismatch")
        return event, payload

    def _verified_approval_authority(
        self,
        connection: Any,
        *,
        approval: Any,
        proposal_row: Any,
        maker_id: str,
        target: ProposalState,
        gate_eval: EvalRun,
        gate_eval_event: Any,
        expected_request_digest: str,
        expected_task_id: str,
        before_seq: int | None,
    ) -> Any:
        """Bind one approval projection to its exact append-only authority event."""

        action = f"promote_improvement:{target.value}"
        resource = self.promotion_resource(proposal_row["proposal_id"])
        request_digest = _digest(expected_request_digest, "expected_request_digest")
        run = connection.execute(
            "SELECT project_id, goal_id FROM runs WHERE run_id = ?",
            (proposal_row["source_run_id"],),
        ).fetchone()
        task = connection.execute(
            "SELECT project_id, goal_id, run_id FROM tasks WHERE task_id = ?",
            (approval["task_id"],),
        ).fetchone()
        requested_at = _instant(approval["requested_at"], "approval.requested_at")
        decided_at = _instant(approval["decided_at"], "approval.decided_at")
        expires_at = _instant(approval["expires_at"], "approval.expires_at")
        if (
            run is None
            or task is None
            or run["project_id"] != proposal_row["project_id"]
            or approval["project_id"] != proposal_row["project_id"]
            or approval["goal_id"] != run["goal_id"]
            or approval["run_id"] != proposal_row["source_run_id"]
            or task["project_id"] != proposal_row["project_id"]
            or task["goal_id"] != run["goal_id"]
            or task["run_id"] != proposal_row["source_run_id"]
            or approval["task_id"] != expected_task_id
            or approval["requester"] != maker_id
            or not isinstance(approval["approver"], str)
            or not approval["approver"]
            or approval["capability"] != Capability.ACTIVE_RULE_PROMOTION.value
            or approval["action"] != action
            or approval["resource"] != resource
            or approval["request_digest"] != request_digest
            or approval["policy_version"] != self.policy_version
            or approval["decision"] != "approved"
            or requested_at != decided_at
            or decided_at <= _instant(gate_eval.created_at, "gate_eval.created_at")
            or expires_at <= decided_at
        ):
            raise IntegrityError(
                f"{target.value} promotion approval projection is invalid"
            )

        events = connection.execute(
            """
            SELECT * FROM events
            WHERE aggregate_type = 'approval' AND aggregate_id = ?
              AND event_type = 'approval_decided'
            """,
            (approval["approval_id"],),
        ).fetchall()
        if len(events) != 1:
            raise IntegrityError(
                f"{target.value} promotion approval authority event is not unique"
            )
        event = events[0]
        try:
            payload = json.loads(event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(
                f"{target.value} promotion approval event payload is invalid"
            ) from exc
        expected_payload = {
            "requester": approval["requester"],
            "capability": approval["capability"],
            "action": approval["action"],
            "resource": approval["resource"],
            "request_digest": approval["request_digest"],
            "decision": approval["decision"],
            "expires_at": approval["expires_at"],
            "authority_binding_digest": approval["authority_binding_digest"],
            "authority_binding_version": approval["authority_binding_version"],
            "decision_gate": approval["decision_gate"],
        }
        self.store._verify_protected_event_authority(
            event,
            expected_handler="policy_engine",
            expected_config_digest=protected_authority_config_digest("policy_engine"),
        )
        occurred_at = _instant(event["occurred_at"], "approval event occurred_at")
        if (
            not isinstance(payload, dict)
            or payload != expected_payload
            or event["aggregate_version"] != 1
            or event["project_id"] != approval["project_id"]
            or event["run_id"] != approval["run_id"]
            or event["task_id"] != approval["task_id"]
            or event["actor"] != approval["approver"]
            or event["correlation_id"] != approval["run_id"]
            or event["policy_version"] != approval["policy_version"]
            or occurred_at < decided_at
            or occurred_at >= expires_at
            or int(event["seq"]) <= int(gate_eval_event["seq"])
        ):
            raise IntegrityError(
                f"{target.value} promotion approval projection/event mismatch"
            )
        if before_seq is not None:
            promotion_event = connection.execute(
                "SELECT project_id, run_id, task_id, occurred_at FROM events WHERE seq = ?",
                (before_seq,),
            ).fetchone()
            if (
                promotion_event is None
                or int(event["seq"]) >= before_seq
                or promotion_event["project_id"] != proposal_row["project_id"]
                or promotion_event["run_id"] != proposal_row["source_run_id"]
                or promotion_event["task_id"] != expected_task_id
                or _instant(
                    promotion_event["occurred_at"], "promotion event occurred_at"
                )
                < occurred_at
                or _instant(
                    promotion_event["occurred_at"], "promotion event occurred_at"
                )
                >= expires_at
            ):
                raise IntegrityError(
                    f"{target.value} promotion approval/event sequence is invalid"
                )
        return event

    @staticmethod
    def _eval_dataset_use_count(
        connection: Any,
        *,
        dataset_split: str,
        dataset_digest: str,
        before_seq: int | None,
    ) -> int:
        query = (
            "SELECT seq, payload_json FROM events "
            "WHERE aggregate_type = 'eval' AND event_type = 'eval_recorded'"
        )
        parameters: tuple[Any, ...] = ()
        if before_seq is not None:
            query += " AND seq < ?"
            parameters = (before_seq,)
        rows = connection.execute(query, parameters).fetchall()
        count = 0
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError(
                    f"evaluation event payload is invalid at seq {row['seq']}"
                ) from exc
            if not isinstance(payload, dict):
                raise IntegrityError(
                    f"evaluation event payload is invalid at seq {row['seq']}"
                )
            if (
                payload.get("dataset_split") == dataset_split
                and payload.get("dataset_digest") == dataset_digest
            ):
                count += 1
        return count

    def _limited_promotion_event(
        self,
        connection: Any,
        *,
        proposal_id: str,
        before_seq: int | None,
    ) -> tuple[Any, dict[str, Any]]:
        query = (
            "SELECT * FROM events "
            "WHERE aggregate_type = 'improvement' AND aggregate_id = ? "
            "AND event_type = 'improvement_promoted'"
        )
        parameters: tuple[Any, ...] = (proposal_id,)
        if before_seq is not None:
            query += " AND seq < ?"
            parameters = (proposal_id, before_seq)
        query += " ORDER BY seq DESC"
        matches: list[tuple[Any, dict[str, Any]]] = []
        for event in connection.execute(query, parameters).fetchall():
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError(
                    f"promotion event payload is invalid at seq {event['seq']}"
                ) from exc
            if isinstance(payload, dict) and payload.get("to") == "limited":
                matches.append((event, payload))
        if not matches:
            raise IntegrityError(
                "active promotion has no linked limited promotion event"
            )
        if len(matches) != 1:
            raise IntegrityError(
                "active promotion has multiple limited promotion events"
            )
        return matches[0]

    def _verified_limited_record(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        before_seq: int | None,
    ) -> tuple[LimitedRulePromotionRecord, Any, Any]:
        limited_event, payload = self._limited_promotion_event(
            connection,
            proposal_id=proposal_row["proposal_id"],
            before_seq=before_seq,
        )
        self.store._verify_protected_event_authority(
            limited_event,
            expected_handler="evaluation_registry",
            expected_config_digest=self.__authority_config_digest,
        )
        raw_record = payload.get("limited_rule_promotion_record")
        if not isinstance(raw_record, dict):
            raise IntegrityError(
                "limited promotion event does not contain a canonical record"
            )
        try:
            record = LimitedRulePromotionRecord.from_dict(raw_record)
        except ContractError as exc:
            raise IntegrityError("limited promotion record is invalid") from exc
        request = record.request
        if (
            request.candidate_id != proposal_row["proposal_id"]
            or request.candidate_digest != proposal_row["candidate_digest"]
            or request.policy_version != self.policy_version
            or request.source_run_id != proposal_row["source_run_id"]
        ):
            raise IntegrityError(
                "limited promotion record candidate authority is invalid"
            )
        expected_request = self._build_limited_request(
            connection,
            proposal_row=proposal_row,
            source_task_id=request.source_task_id,
            verification_evidence_id=request.verification_evidence_id,
            scope=request.scope,
            actual_outcome_kind=request.actual_outcome_kind,
            actual_outcome=request.actual_outcome,
            non_goals=request.non_goals,
            review_condition=request.review_condition,
            rollback_or_retirement_path=request.rollback_or_retirement_path,
            non_claim_boundary=request.non_claim_boundary,
            before_seq=int(limited_event["seq"]),
        )
        approval = connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ?",
            (record.owner_approval_id,),
        ).fetchone()
        if approval is None:
            raise IntegrityError("limited promotion approval projection is missing")
        heldout_row = connection.execute(
            "SELECT * FROM eval_runs WHERE eval_id = ?",
            (request.promotion_validation_eval_id,),
        ).fetchone()
        if heldout_row is None:
            raise IntegrityError("limited promotion validation projection is missing")
        heldout = _eval(heldout_row)
        heldout_event, _ = self._verified_eval_event(connection, heldout)
        proposer_event, _ = self._verified_proposal_event(connection, proposal_row)
        approval_event = self._verified_approval_authority(
            connection,
            approval=approval,
            proposal_row=proposal_row,
            maker_id=str(proposer_event["actor"]),
            target=ProposalState.LIMITED,
            gate_eval=heldout,
            gate_eval_event=heldout_event,
            expected_request_digest=expected_request.request_digest,
            expected_task_id=request.source_task_id,
            before_seq=int(limited_event["seq"]),
        )
        evidence, _, run_delivery_seq = self._verified_limited_source_evidence(
            connection,
            proposal_row=proposal_row,
            source_task_id=request.source_task_id,
            verification_evidence_id=request.verification_evidence_id,
            before_seq=int(limited_event["seq"]),
        )
        expected_record = LimitedRulePromotionRecord(
            promotion_record_id=record.promotion_record_id,
            request=expected_request,
            from_state=ProposalState.OWNER_REVIEW.value,
            owner_approval_id=approval["approval_id"],
            owner_principal_id=approval["approver"],
            approved_at=approval["decided_at"],
        )
        expected_payload = {
            "from": ProposalState.OWNER_REVIEW.value,
            "to": ProposalState.LIMITED.value,
            "approval_id": approval["approval_id"],
            "limited_rule_promotion_record": record.to_dict(),
        }
        if (
            expected_record != record
            or payload != expected_payload
            or evidence["claim"] != record.request.actual_outcome
            or limited_event["project_id"] != proposal_row["project_id"]
            or limited_event["run_id"] != proposal_row["source_run_id"]
            or limited_event["task_id"] != request.source_task_id
            or limited_event["actor"] != record.owner_principal_id
            or limited_event["correlation_id"] != proposal_row["source_run_id"]
            or limited_event["policy_version"] != self.policy_version
            or not (
                run_delivery_seq
                < int(approval_event["seq"])
                < int(limited_event["seq"])
            )
        ):
            raise IntegrityError(
                "limited promotion record does not match persisted authority"
            )
        return record, limited_event, approval_event

    def get_limited_rule_promotion_record(
        self, proposal_id: str
    ) -> LimitedRulePromotionRecord:
        """Chain-first readback of the exact candidate->limited decision."""

        proposal_id = _text(proposal_id, "proposal_id")
        with self.store.transaction() as connection:
            self.store.verify_event_chain(connection)
            proposal_row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if proposal_row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            if proposal_row["state"] not in {
                ProposalState.LIMITED.value,
                ProposalState.ACTIVE.value,
            }:
                raise NotFoundError(
                    f"limited rule promotion record not found: {proposal_id}"
                )
            record, _, _ = self._verified_limited_record(
                connection, proposal_row=proposal_row, before_seq=None
            )
            if (
                proposal_row["state"] == ProposalState.LIMITED.value
                and proposal_row["owner_approval_id"] != record.owner_approval_id
            ):
                raise IntegrityError(
                    "limited promotion record does not match proposal projection"
                )
            return record

    def _verified_sealed_custody(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        sealed: EvalRun,
        sealed_event: Any,
        before_seq: int | None,
    ) -> tuple[Any, Any]:
        row = connection.execute(
            "SELECT * FROM sealed_custody_attestations WHERE proposal_id = ?",
            (proposal_row["proposal_id"],),
        ).fetchone()
        if row is None:
            raise AuthorizationError(
                "active promotion requires verified external sealed custody"
            )
        events = connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'sealed_custody' "
            "AND aggregate_id = ? AND event_type = 'sealed_custody_attested'",
            (row["attestation_id"],),
        ).fetchall()
        if len(events) != 1:
            raise IntegrityError("sealed custody authority event is not unique")
        event = events[0]
        try:
            payload = json.loads(event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("sealed custody authority event is invalid") from exc
        envelope = {
            "attestation_id": row["attestation_id"],
            "proposal_id": row["proposal_id"],
            "eval_id": row["eval_id"],
            "project_id": row["project_id"],
            "candidate_digest": row["candidate_digest"],
            "dataset_digest": row["dataset_digest"],
            "eval_attestation_digest": row["eval_attestation_digest"],
            "evaluator_principal_id": row["evaluator_principal_id"],
            "custody_provider": row["custody_provider"],
            "custodian_id": row["custodian_id"],
            "policy_version": row["policy_version"],
        }
        expected_payload = {
            **envelope,
            "attestation_digest": content_hash(envelope),
            "verified_at": row["verified_at"],
        }
        self.store._verify_protected_event_authority(
            event,
            expected_handler="evaluation_registry",
            expected_config_digest=self.__authority_config_digest,
        )
        upper_bound = before_seq if before_seq is not None else 2**63 - 1
        if (
            payload != expected_payload
            or row["attestation_digest"] != expected_payload["attestation_digest"]
            or row["eval_id"] != sealed.eval_id
            or row["project_id"] != proposal_row["project_id"]
            or row["candidate_digest"] != proposal_row["candidate_digest"]
            or row["dataset_digest"] != sealed.dataset_digest
            or row["eval_attestation_digest"] != sealed.attestation_digest
            or row["evaluator_principal_id"] != sealed.evaluator
            or row["policy_version"] != self.policy_version
            or _instant(row["verified_at"], "sealed custody verified_at")
            > _instant(event["occurred_at"], "sealed custody event occurred_at")
            or event["aggregate_version"] != 1
            or event["project_id"] != proposal_row["project_id"]
            or event["run_id"] != proposal_row["source_run_id"]
            or event["task_id"] is not None
            or event["actor"] != row["custodian_id"]
            or event["correlation_id"] != proposal_row["source_run_id"]
            or event["policy_version"] != self.policy_version
            or not int(sealed_event["seq"]) < int(event["seq"]) < upper_bound
        ):
            raise IntegrityError("sealed custody projection/event mismatch")
        return row, event

    def _active_request_digest(
        self,
        *,
        proposal_row: Any,
        limited_record: LimitedRulePromotionRecord,
        sealed: EvalRun,
        custody: Any,
    ) -> str:
        return content_hash(
            {
                "proposal_id": proposal_row["proposal_id"],
                "candidate_digest": proposal_row["candidate_digest"],
                "policy_version": self.policy_version,
                "target": ProposalState.ACTIVE.value,
                "limited_rule_promotion_record": limited_record.to_dict(),
                "sealed_eval_id": sealed.eval_id,
                "sealed_dataset_digest": sealed.dataset_digest,
                "sealed_attestation_digest": sealed.attestation_digest,
                "sealed_evaluator_principal_id": sealed.evaluator,
                "sealed_custody_attestation_id": custody["attestation_id"],
                "sealed_custody_provider": custody["custody_provider"],
                "sealed_custodian_id": custody["custodian_id"],
                "sealed_custody_attestation_digest": custody["attestation_digest"],
                "sealed_custody_verified_at": custody["verified_at"],
            }
        )

    def _assemble_active_rule_promotion_record(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        approval: Any,
        promotion_record_id: str,
        before_seq: int | None,
    ) -> ActiveRulePromotionRecord:
        sealed_row = connection.execute(
            "SELECT * FROM eval_runs WHERE eval_id = ?",
            (proposal_row["sealed_eval_id"],),
        ).fetchone()
        if sealed_row is None:
            raise IntegrityError("active promotion requires a persisted sealed eval")
        sealed = _eval(sealed_row)
        if (
            not sealed.clean_pass
            or sealed.dataset_split != "sealed"
            or sealed.project_id != proposal_row["project_id"]
            or sealed.candidate_digest != proposal_row["candidate_digest"]
        ):
            raise IntegrityError("active promotion sealed evaluation is invalid")
        sealed_event, sealed_payload = self._verified_eval_event(connection, sealed)
        self._verified_eval_attachment_event(
            connection,
            proposal_row=proposal_row,
            evaluation=sealed,
            evaluation_event=sealed_event,
            before_seq=before_seq,
        )
        if sealed_payload.get("result_influenced_edits") is not False:
            raise AuthorizationError(
                "sealed result that influenced edits cannot support active promotion"
            )
        proposer_event, _ = self._verified_proposal_event(connection, proposal_row)
        limited_record, limited_event, _ = self._verified_limited_record(
            connection, proposal_row=proposal_row, before_seq=before_seq
        )
        custody, custody_event = self._verified_sealed_custody(
            connection,
            proposal_row=proposal_row,
            sealed=sealed,
            sealed_event=sealed_event,
            before_seq=before_seq,
        )
        active_request_digest = self._active_request_digest(
            proposal_row=proposal_row,
            limited_record=limited_record,
            sealed=sealed,
            custody=custody,
        )
        active_approval_event = self._verified_approval_authority(
            connection,
            approval=approval,
            proposal_row=proposal_row,
            maker_id=str(proposer_event["actor"]),
            target=ProposalState.ACTIVE,
            gate_eval=sealed,
            gate_eval_event=sealed_event,
            expected_request_digest=active_request_digest,
            expected_task_id=limited_record.request.source_task_id,
            before_seq=before_seq,
        )
        owner_id = str(approval["approver"])
        if (
            len(
                {
                    str(proposer_event["actor"]),
                    sealed.evaluator,
                    custody["custodian_id"],
                    owner_id,
                }
            )
            != 4
        ):
            raise AuthorizationError(
                "proposal maker, sealed evaluator, external custodian, and Owner "
                "approver must be distinct"
            )
        if not (
            int(limited_event["seq"])
            < int(sealed_event["seq"])
            < int(custody_event["seq"])
            < int(active_approval_event["seq"])
        ):
            raise IntegrityError(
                "limited/sealed/custody/active-approval order is invalid"
            )
        limited = limited_record.request
        return ActiveRulePromotionRecord(
            promotion_record_id=_text(promotion_record_id, "promotion_record_id"),
            candidate_id=proposal_row["proposal_id"],
            candidate_digest=proposal_row["candidate_digest"],
            policy_version=self.policy_version,
            promotion_validation_eval_id=limited.promotion_validation_eval_id,
            promotion_validation_dataset_digest=(
                limited.promotion_validation_dataset_digest
            ),
            promotion_validation_attestation_digest=(
                limited.promotion_validation_attestation_digest
            ),
            promotion_validation_query_count=limited.promotion_validation_query_count,
            promotion_validation_status=limited.promotion_validation_status,
            limited_promotion_record_id=limited_record.promotion_record_id,
            limited_promotion_record_digest=limited_record.record_digest,
            source_task_id=limited.source_task_id,
            verification_evidence_id=limited.verification_evidence_id,
            verification_evidence_digest=limited.verification_evidence_digest,
            actual_outcome_kind=limited.actual_outcome_kind,
            actual_outcome=limited.actual_outcome,
            from_state=ProposalState.LIMITED.value,
            target_state=ProposalState.ACTIVE.value,
            proposal_maker_principal_id=str(proposer_event["actor"]),
            evaluator_principal_id=sealed.evaluator,
            evaluator_digest=content_hash(
                {
                    "evaluator_principal_id": sealed.evaluator,
                    "evaluator_version": sealed.evaluator_version,
                }
            ),
            sealed_eval_id=sealed.eval_id,
            sealed_dataset_digest=sealed.dataset_digest,
            sealed_dataset_use_count=self._eval_dataset_use_count(
                connection,
                dataset_split="sealed",
                dataset_digest=sealed.dataset_digest,
                before_seq=before_seq,
            ),
            sealed_result_influenced_edits=False,
            sealed_attestation_digest=sealed.attestation_digest,
            sealed_custody_attestation_id=custody["attestation_id"],
            sealed_custody_provider=custody["custody_provider"],
            sealed_custodian_id=custody["custodian_id"],
            sealed_custody_attestation_digest=custody["attestation_digest"],
            sealed_custody_verified_at=custody["verified_at"],
            safety_hard_failures=len(sealed.safety_failures),
            eval_status=sealed.status,
            evaluated_at=sealed.created_at,
            owner_approval_id=approval["approval_id"],
            owner_principal_id=owner_id,
            approved_at=approval["decided_at"],
            scope=limited.scope,
            review_condition=limited.review_condition,
            non_goals=limited.non_goals,
            rollback_or_retirement_path=limited.rollback_or_retirement_path,
            non_claim_boundary=_ACTIVE_RULE_NON_CLAIM,
        )

    def get_active_rule_promotion_record(
        self, proposal_id: str
    ) -> ActiveRulePromotionRecord:
        """Read and independently verify the canonical active-promotion record."""

        proposal_id = _text(proposal_id, "proposal_id")
        with self.store.transaction() as connection:
            # Chain verification and all authority/projection reads share one
            # SQLite snapshot. There is no verify/read window in which a
            # different history can become the basis of the returned record.
            self.store.verify_event_chain(connection)
            proposal_row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if proposal_row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            candidates: list[tuple[Any, dict[str, Any]]] = []
            for event in connection.execute(
                "SELECT * FROM events "
                "WHERE aggregate_type = 'improvement' AND aggregate_id = ? "
                "AND event_type = 'improvement_promoted' ORDER BY seq",
                (proposal_id,),
            ).fetchall():
                try:
                    payload = json.loads(event["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise IntegrityError(
                        f"promotion event payload is invalid at seq {event['seq']}"
                    ) from exc
                if isinstance(payload, dict) and payload.get("to") == "active":
                    candidates.append((event, payload))
            if not candidates:
                raise NotFoundError(
                    f"active rule promotion record not found: {proposal_id}"
                )
            if len(candidates) != 1:
                raise IntegrityError(
                    "proposal has multiple canonical active promotion events"
                )
            event, payload = candidates[0]
            self.store._verify_protected_event_authority(
                event,
                expected_handler="evaluation_registry",
                expected_config_digest=self.__authority_config_digest,
            )
            raw_record = payload.get("active_rule_promotion_record")
            if not isinstance(raw_record, dict):
                raise IntegrityError(
                    "active promotion event does not contain a canonical record"
                )
            try:
                record = ActiveRulePromotionRecord.from_dict(raw_record)
            except ContractError as exc:
                raise IntegrityError(
                    "active promotion event contains an invalid canonical record"
                ) from exc
            approval = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (record.owner_approval_id,),
            ).fetchone()
            if approval is None:
                raise IntegrityError("active promotion approval projection is missing")
            expected = self._assemble_active_rule_promotion_record(
                connection,
                proposal_row=proposal_row,
                approval=approval,
                promotion_record_id=record.promotion_record_id,
                before_seq=int(event["seq"]),
            )
            expected_payload = {
                "from": ProposalState.LIMITED.value,
                "to": ProposalState.ACTIVE.value,
                "approval_id": record.owner_approval_id,
                "active_rule_promotion_record": record.to_dict(),
            }
            if (
                expected != record
                or payload != expected_payload
                or event["project_id"] != proposal_row["project_id"]
                or event["run_id"] != proposal_row["source_run_id"]
                or event["task_id"] != record.source_task_id
                or event["actor"] != record.owner_principal_id
                or event["correlation_id"] != proposal_row["source_run_id"]
                or event["policy_version"] != record.policy_version
                or proposal_row["state"] != ProposalState.ACTIVE.value
                or proposal_row["owner_approval_id"] != record.owner_approval_id
            ):
                raise IntegrityError(
                    "active promotion record does not match persisted authority"
                )
            return record

    def promotion_request_digest(
        self,
        proposal_id: str,
        candidate_digest: str,
        target: ProposalState | str,
        *,
        limited_request: LimitedRulePromotionRequest | None = None,
    ) -> str:
        state = ProposalState(str(target))
        proposal_id = _text(proposal_id, "proposal_id")
        candidate_digest = _digest(candidate_digest, "candidate_digest")
        if state is ProposalState.LIMITED:
            if not isinstance(limited_request, LimitedRulePromotionRequest):
                raise ContractError(
                    "limited promotion request is required for exact approval"
                )
            if (
                limited_request.candidate_id != proposal_id
                or limited_request.candidate_digest != candidate_digest
                or limited_request.policy_version != self.policy_version
                or limited_request.target_state != state.value
            ):
                raise ContractError(
                    "limited promotion request does not match proposal authority"
                )
            return limited_request.request_digest
        if state is not ProposalState.ACTIVE:
            raise TransitionError("promotion target must be limited or active")
        if limited_request is not None:
            raise ContractError("active promotion derives the persisted limited record")
        with self.store.transaction() as connection:
            self.store.verify_event_chain(connection)
            proposal_row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if (
                proposal_row is None
                or proposal_row["candidate_digest"] != candidate_digest
                or proposal_row["state"] != ProposalState.LIMITED.value
            ):
                raise TransitionError(
                    "active approval requires the exact persisted limited proposal"
                )
            limited_record, _, _ = self._verified_limited_record(
                connection, proposal_row=proposal_row, before_seq=None
            )
            sealed_row = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?",
                (proposal_row["sealed_eval_id"],),
            ).fetchone()
            if sealed_row is None:
                raise TransitionError("a clean sealed evaluation is required")
            sealed = _eval(sealed_row)
            sealed_event, _ = self._verified_eval_event(connection, sealed)
            self._verified_eval_attachment_event(
                connection,
                proposal_row=proposal_row,
                evaluation=sealed,
                evaluation_event=sealed_event,
                before_seq=None,
            )
            custody, _ = self._verified_sealed_custody(
                connection,
                proposal_row=proposal_row,
                sealed=sealed,
                sealed_event=sealed_event,
                before_seq=None,
            )
            return self._active_request_digest(
                proposal_row=proposal_row,
                limited_record=limited_record,
                sealed=sealed,
                custody=custody,
            )

    @staticmethod
    def promotion_resource(proposal_id: str) -> str:
        return f"improvement://proposals/{_text(proposal_id, 'proposal_id')}"

    def promote(
        self,
        proposal_id: str,
        *,
        target: ProposalState | str,
        approval_id: str,
        actor: VerifiedPrincipal,
        limited_request: LimitedRulePromotionRequest | None = None,
    ) -> ImprovementProposal:
        proposal_id = _text(proposal_id, "proposal_id")
        approval_id = _text(approval_id, "approval_id")
        try:
            target_state = ProposalState(str(target))
        except ValueError as exc:
            raise TransitionError(f"unsupported proposal state: {target}") from exc
        if target_state not in {ProposalState.LIMITED, ProposalState.ACTIVE}:
            raise TransitionError("promotion target must be limited or active")
        with self.store.transaction(immediate=True) as connection:
            self.store.verify_event_chain(connection)
            actor_id = self.identity.require_role_in_transaction(
                connection, actor, Role.OWNER
            ).principal_id
            row = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"improvement proposal not found: {proposal_id}")
            current = ProposalState(row["state"])
            allowed_source = (
                ProposalState.OWNER_REVIEW
                if target_state is ProposalState.LIMITED
                else ProposalState.LIMITED
            )
            if current is not allowed_source:
                raise TransitionError(
                    f"proposal must be {allowed_source.value} before {target_state.value} promotion"
                )
            heldout_row = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (row["held_out_eval_id"],)
            ).fetchone()
            if heldout_row is None or not _eval(heldout_row).clean_pass:
                raise TransitionError("clean held-out evaluation is required")
            heldout = _eval(heldout_row)
            proposer_event, _ = self._verified_proposal_event(connection, row)
            if target_state is ProposalState.LIMITED:
                if not isinstance(limited_request, LimitedRulePromotionRequest):
                    raise ContractError(
                        "canonical limited promotion request is required"
                    )
                expected_limited_request = self._build_limited_request(
                    connection,
                    proposal_row=row,
                    source_task_id=limited_request.source_task_id,
                    verification_evidence_id=(limited_request.verification_evidence_id),
                    scope=limited_request.scope,
                    actual_outcome_kind=limited_request.actual_outcome_kind,
                    actual_outcome=limited_request.actual_outcome,
                    non_goals=limited_request.non_goals,
                    review_condition=limited_request.review_condition,
                    rollback_or_retirement_path=(
                        limited_request.rollback_or_retirement_path
                    ),
                    non_claim_boundary=limited_request.non_claim_boundary,
                    before_seq=None,
                )
                if expected_limited_request != limited_request:
                    raise IntegrityError(
                        "limited promotion request drifted from persisted evidence"
                    )
                gate_eval = heldout
                request_digest = limited_request.request_digest
                source_task_id = limited_request.source_task_id
                heldout_event, _ = self._verified_eval_event(connection, heldout)
                _, _, run_delivery_seq = self._verified_limited_source_evidence(
                    connection,
                    proposal_row=row,
                    source_task_id=source_task_id,
                    verification_evidence_id=(limited_request.verification_evidence_id),
                    before_seq=None,
                )
            else:
                if limited_request is not None:
                    raise ContractError(
                        "active promotion derives the exact persisted limited record"
                    )
                sealed_row = connection.execute(
                    "SELECT * FROM eval_runs WHERE eval_id = ?",
                    (row["sealed_eval_id"],),
                ).fetchone()
                if sealed_row is None or not _eval(sealed_row).clean_pass:
                    raise TransitionError(
                        "clean sealed evaluation is required for active promotion"
                    )
                gate_eval = _eval(sealed_row)
                sealed_event, _ = self._verified_eval_event(connection, gate_eval)
                self._verified_eval_attachment_event(
                    connection,
                    proposal_row=row,
                    evaluation=gate_eval,
                    evaluation_event=sealed_event,
                    before_seq=None,
                )
                persisted_limited, _, _ = self._verified_limited_record(
                    connection, proposal_row=row, before_seq=None
                )
                custody, _ = self._verified_sealed_custody(
                    connection,
                    proposal_row=row,
                    sealed=gate_eval,
                    sealed_event=sealed_event,
                    before_seq=None,
                )
                request_digest = self._active_request_digest(
                    proposal_row=row,
                    limited_record=persisted_limited,
                    sealed=gate_eval,
                    custody=custody,
                )
                source_task_id = persisted_limited.request.source_task_id
            action = f"promote_improvement:{target_state.value}"
            resource = self.promotion_resource(proposal_id)
            approval = connection.execute(
                """
                SELECT * FROM approvals
                WHERE approval_id = ? AND project_id = ? AND run_id = ?
                  AND task_id = ?
                  AND approver = ? AND capability = ? AND action = ?
                  AND resource = ? AND request_digest = ?
                  AND policy_version = ?
                  AND decision = 'approved' AND julianday(expires_at) > julianday('now')
                  AND julianday(decided_at) > julianday(?)
                """,
                (
                    approval_id,
                    row["project_id"],
                    row["source_run_id"],
                    source_task_id,
                    actor_id,
                    Capability.ACTIVE_RULE_PROMOTION.value,
                    action,
                    resource,
                    request_digest,
                    self.policy_version,
                    gate_eval.created_at,
                ),
            ).fetchone()
            if approval is None:
                raise AuthorizationError(
                    "exact, live owner approval for this promotion is required"
                )
            version = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
                "WHERE aggregate_type = 'improvement' AND aggregate_id = ?",
                (proposal_id,),
            ).fetchone()[0]
            if target_state is ProposalState.LIMITED:
                assert isinstance(limited_request, LimitedRulePromotionRequest)
                approval_event = self._verified_approval_authority(
                    connection,
                    approval=approval,
                    proposal_row=row,
                    maker_id=str(proposer_event["actor"]),
                    target=ProposalState.LIMITED,
                    gate_eval=gate_eval,
                    gate_eval_event=heldout_event,
                    expected_request_digest=request_digest,
                    expected_task_id=source_task_id,
                    before_seq=None,
                )
                if run_delivery_seq >= int(approval_event["seq"]):
                    raise AuthorizationError(
                        "Owner limited approval must follow source Run/Task delivery"
                    )
                limited_record = LimitedRulePromotionRecord(
                    promotion_record_id=str(uuid.uuid4()),
                    request=limited_request,
                    from_state=ProposalState.OWNER_REVIEW.value,
                    owner_approval_id=approval_id,
                    owner_principal_id=actor_id,
                    approved_at=approval["decided_at"],
                )
                promotion_payload: dict[str, Any] = {
                    "from": current.value,
                    "to": target_state.value,
                    "approval_id": approval_id,
                    "limited_rule_promotion_record": limited_record.to_dict(),
                }
            else:
                promotion_record = self._assemble_active_rule_promotion_record(
                    connection,
                    proposal_row=row,
                    approval=approval,
                    promotion_record_id=str(uuid.uuid4()),
                    before_seq=None,
                )
                promotion_payload = {
                    "from": current.value,
                    "to": target_state.value,
                    "approval_id": approval_id,
                    "active_rule_promotion_record": promotion_record.to_dict(),
                }
            self.store.append_event(
                connection,
                aggregate_type="improvement",
                aggregate_id=proposal_id,
                expected_version=int(version),
                project_id=row["project_id"],
                run_id=row["source_run_id"],
                task_id=source_task_id,
                event_type="improvement_promoted",
                actor=actor_id,
                command_id=str(uuid.uuid4()),
                correlation_id=row["source_run_id"],
                policy_version=self.policy_version,
                payload=promotion_payload,
                command_authority=self.__command_authority,
                command_owner=self,
            )
            connection.execute(
                "UPDATE improvement_proposals SET state = ?, owner_approval_id = ?, updated_at = ? "
                "WHERE proposal_id = ?",
                (target_state.value, approval_id, utc_now(), proposal_id),
            )
            updated = connection.execute(
                "SELECT * FROM improvement_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            return _proposal(updated)
