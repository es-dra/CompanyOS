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
    IntegrityError,
    NotFoundError,
    TransitionError,
)
from .identity import IdentityManager, Role, VerifiedPrincipal
from .store import SQLiteStore
from .types import Capability, ProposalState, canonical_json, content_hash, utc_now


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
_ACTIVE_RULE_NON_GOALS = (
    "human_acceptance",
    "business_validation",
    "durable_memory_promotion",
    "public_release",
    "external_sealed_custody",
)
_ACTIVE_RULE_NON_CLAIM = (
    "structure-verified single-host promotion record only; no external custody, "
    "human acceptance, business validation, legal conclusion, public release, "
    "or production autonomy claim"
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
    safety_hard_failures: int
    eval_status: str
    evaluated_at: str
    owner_approval_id: str
    owner_principal_id: str
    approved_at: str
    scope: str
    review_date: str
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
            "from_state",
            "target_state",
            "proposal_maker_principal_id",
            "evaluator_principal_id",
            "sealed_eval_id",
            "eval_status",
            "owner_approval_id",
            "owner_principal_id",
            "scope",
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
            "evaluator_digest",
            "sealed_dataset_digest",
            "sealed_attestation_digest",
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
                }
            )
            != 3
        ):
            raise ContractError(
                "proposal maker, evaluator, and owner approver must be distinct"
            )
        evaluated = _instant(self.evaluated_at, "evaluated_at")
        approved = _instant(self.approved_at, "approved_at")
        review = _instant(self.review_date, "review_date")
        if approved <= evaluated:
            raise ContractError("approved_at must be later than evaluated_at")
        if review <= approved:
            raise ContractError("review_date must be later than approved_at")
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
    def verify(self, attestation: EvalResultAttestation) -> object | None: ...


class DenyAllEvalResultVerifier:
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
    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
        result_verifier: EvalResultVerifier | None = None,
    ):
        self.store = store
        self.policy_version = policy_version
        self.identity = identity or IdentityManager(store)
        self.result_verifier = result_verifier or DenyAllEvalResultVerifier()

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
        verifier_result = self.result_verifier.verify(attestation)
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

    def _verified_eval_event(
        self, connection: Any, evaluation: EvalRun
    ) -> tuple[Any, dict[str, Any]]:
        events = connection.execute(
            """
            SELECT seq, aggregate_version, project_id, run_id, task_id, actor,
                   correlation_id, policy_version, occurred_at, payload_json
            FROM events
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

    def _verified_proposal_event(
        self, connection: Any, proposal_row: Any
    ) -> tuple[Any, dict[str, Any]]:
        events = connection.execute(
            """
            SELECT seq, aggregate_version, project_id, run_id, task_id, actor,
                   correlation_id, policy_version, occurred_at, payload_json
            FROM events
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
        before_seq: int | None,
    ) -> Any:
        """Bind one approval projection to its exact append-only authority event."""

        action = f"promote_improvement:{target.value}"
        resource = self.promotion_resource(proposal_row["proposal_id"])
        request_digest = self.promotion_request_digest(
            proposal_row["proposal_id"],
            proposal_row["candidate_digest"],
            target,
        )
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
            SELECT seq, aggregate_version, project_id, run_id, task_id, actor,
                   correlation_id, policy_version, occurred_at, payload_json
            FROM events
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
        }
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
                or promotion_event["task_id"] is not None
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
            "SELECT seq, project_id, run_id, task_id, actor, correlation_id, "
            "policy_version, occurred_at, payload_json FROM events "
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

    def _build_active_rule_promotion_record(
        self,
        connection: Any,
        *,
        proposal_row: Any,
        approval: Any,
        promotion_record_id: str,
        before_seq: int | None,
    ) -> ActiveRulePromotionRecord:
        heldout_row = connection.execute(
            "SELECT * FROM eval_runs WHERE eval_id = ?",
            (proposal_row["held_out_eval_id"],),
        ).fetchone()
        sealed_row = connection.execute(
            "SELECT * FROM eval_runs WHERE eval_id = ?",
            (proposal_row["sealed_eval_id"],),
        ).fetchone()
        if heldout_row is None or sealed_row is None:
            raise IntegrityError(
                "active promotion requires persisted promotion-validation and sealed evals"
            )
        heldout = _eval(heldout_row)
        sealed = _eval(sealed_row)
        if (
            not heldout.clean_pass
            or heldout.dataset_split != "held_out"
            or not sealed.clean_pass
            or sealed.dataset_split != "sealed"
            or heldout.project_id != proposal_row["project_id"]
            or sealed.project_id != proposal_row["project_id"]
            or heldout.candidate_digest != proposal_row["candidate_digest"]
            or sealed.candidate_digest != proposal_row["candidate_digest"]
        ):
            raise IntegrityError("active promotion evaluation projections are invalid")
        heldout_event, _ = self._verified_eval_event(connection, heldout)
        sealed_event, sealed_payload = self._verified_eval_event(connection, sealed)
        proposer, _ = self._verified_proposal_event(connection, proposal_row)
        maker_id = str(proposer["actor"])
        limited_event, limited_payload = self._limited_promotion_event(
            connection, proposal_id=proposal_row["proposal_id"], before_seq=before_seq
        )
        limited_approval_id = limited_payload.get("approval_id")
        if not isinstance(limited_approval_id, str) or not limited_approval_id:
            raise IntegrityError("linked limited promotion approval id is invalid")
        limited_approval = connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ?",
            (limited_approval_id,),
        ).fetchone()
        if limited_approval is None:
            raise IntegrityError("linked limited promotion approval is missing")
        limited_approval_event = self._verified_approval_authority(
            connection,
            approval=limited_approval,
            proposal_row=proposal_row,
            maker_id=maker_id,
            target=ProposalState.LIMITED,
            gate_eval=heldout,
            gate_eval_event=heldout_event,
            before_seq=int(limited_event["seq"]),
        )
        active_approval_event = self._verified_approval_authority(
            connection,
            approval=approval,
            proposal_row=proposal_row,
            maker_id=maker_id,
            target=ProposalState.ACTIVE,
            gate_eval=sealed,
            gate_eval_event=sealed_event,
            before_seq=before_seq,
        )
        if not (
            int(proposer["seq"])
            < int(heldout_event["seq"])
            < int(limited_approval_event["seq"])
            < int(limited_event["seq"])
            < int(sealed_event["seq"])
            < int(active_approval_event["seq"])
        ):
            raise IntegrityError(
                "proposal/eval/approval/promotion authority order is invalid"
            )
        if before_seq is not None and int(active_approval_event["seq"]) >= before_seq:
            raise IntegrityError("active approval must precede active promotion event")
        owner_id = str(approval["approver"])
        if len({maker_id, sealed.evaluator, owner_id}) != 3:
            raise AuthorizationError(
                "proposal maker, sealed evaluator, and owner approver must be distinct"
            )
        query_count = self._eval_dataset_use_count(
            connection,
            dataset_split="held_out",
            dataset_digest=heldout.dataset_digest,
            before_seq=before_seq,
        )
        sealed_use_count = self._eval_dataset_use_count(
            connection,
            dataset_split="sealed",
            dataset_digest=sealed.dataset_digest,
            before_seq=before_seq,
        )
        limited_record_id = limited_payload.get("promotion_record_id")
        limited_expected = {
            "from": ProposalState.OWNER_REVIEW.value,
            "to": ProposalState.LIMITED.value,
            "approval_id": limited_approval["approval_id"],
            "promotion_record_id": limited_record_id,
            "candidate_id": proposal_row["proposal_id"],
            "candidate_digest": proposal_row["candidate_digest"],
            "policy_version": self.policy_version,
            "promotion_validation_eval_id": heldout.eval_id,
            "promotion_validation_dataset_digest": heldout.dataset_digest,
            "promotion_validation_attestation_digest": heldout.attestation_digest,
            "promotion_validation_query_count": self._eval_dataset_use_count(
                connection,
                dataset_split="held_out",
                dataset_digest=heldout.dataset_digest,
                before_seq=int(limited_event["seq"]),
            ),
            "promotion_validation_status": "pass",
            "approved_at": limited_approval["decided_at"],
            "evaluated_at": heldout.created_at,
            "eval_event_seq": int(heldout_event["seq"]),
        }
        if (
            not isinstance(limited_record_id, str)
            or not limited_record_id
            or limited_payload != limited_expected
            or limited_event["project_id"] != proposal_row["project_id"]
            or limited_event["run_id"] != proposal_row["source_run_id"]
            or limited_event["task_id"] is not None
            or limited_event["actor"] != limited_approval["approver"]
            or limited_event["correlation_id"] != proposal_row["source_run_id"]
            or limited_event["policy_version"] != self.policy_version
            or _instant(limited_event["occurred_at"], "limited event occurred_at")
            < _instant(limited_approval["decided_at"], "limited approved_at")
            or _instant(limited_event["occurred_at"], "limited event occurred_at")
            <= _instant(heldout.created_at, "heldout evaluated_at")
        ):
            raise IntegrityError("linked limited promotion record is invalid")
        if sealed_payload.get("result_influenced_edits") is not False:
            raise AuthorizationError(
                "sealed result that influenced edits cannot support active promotion"
            )
        return ActiveRulePromotionRecord(
            promotion_record_id=_text(promotion_record_id, "promotion_record_id"),
            candidate_id=proposal_row["proposal_id"],
            candidate_digest=proposal_row["candidate_digest"],
            policy_version=self.policy_version,
            promotion_validation_eval_id=heldout.eval_id,
            promotion_validation_dataset_digest=heldout.dataset_digest,
            promotion_validation_attestation_digest=heldout.attestation_digest,
            promotion_validation_query_count=query_count,
            promotion_validation_status="pass",
            limited_promotion_record_id=limited_record_id,
            from_state=ProposalState.LIMITED.value,
            target_state=ProposalState.ACTIVE.value,
            proposal_maker_principal_id=maker_id,
            evaluator_principal_id=sealed.evaluator,
            evaluator_digest=content_hash(
                {
                    "evaluator_principal_id": sealed.evaluator,
                    "evaluator_version": sealed.evaluator_version,
                }
            ),
            sealed_eval_id=sealed.eval_id,
            sealed_dataset_digest=sealed.dataset_digest,
            sealed_dataset_use_count=sealed_use_count,
            sealed_result_influenced_edits=False,
            sealed_attestation_digest=sealed.attestation_digest,
            safety_hard_failures=len(sealed.safety_failures),
            eval_status=sealed.status,
            evaluated_at=sealed.created_at,
            owner_approval_id=approval["approval_id"],
            owner_principal_id=owner_id,
            approved_at=approval["decided_at"],
            scope=proposal_row["editable_surface"],
            review_date=approval["expires_at"],
            non_goals=_ACTIVE_RULE_NON_GOALS,
            rollback_or_retirement_path=proposal_row["rollback_route"],
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
                "SELECT seq, project_id, run_id, task_id, actor, correlation_id, "
                "policy_version, occurred_at, payload_json FROM events "
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
            expected = self._build_active_rule_promotion_record(
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
                or event["task_id"] is not None
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

    @staticmethod
    def promotion_request_digest(
        proposal_id: str, candidate_digest: str, target: ProposalState | str
    ) -> str:
        state = ProposalState(str(target))
        return content_hash(
            {
                "proposal_id": proposal_id,
                "candidate_digest": candidate_digest,
                "target": state.value,
            }
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
            heldout = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (row["held_out_eval_id"],)
            ).fetchone()
            if heldout is None or not _eval(heldout).clean_pass:
                raise TransitionError("clean held-out evaluation is required")
            gate_eval = _eval(heldout)
            if target_state is ProposalState.ACTIVE:
                sealed = connection.execute(
                    "SELECT * FROM eval_runs WHERE eval_id = ?",
                    (row["sealed_eval_id"],),
                ).fetchone()
                if sealed is None or not _eval(sealed).clean_pass:
                    raise TransitionError(
                        "clean sealed evaluation is required for active promotion"
                    )
                gate_eval = _eval(sealed)
                proposer = connection.execute(
                    "SELECT actor FROM events WHERE aggregate_type = 'improvement' "
                    "AND aggregate_id = ? AND event_type = 'improvement_proposed'",
                    (proposal_id,),
                ).fetchone()
                if proposer is None or actor_id in {
                    proposer["actor"],
                    gate_eval.evaluator,
                }:
                    raise AuthorizationError(
                        "proposal maker, sealed evaluator, and owner approver must be distinct"
                    )
            request_digest = self.promotion_request_digest(
                proposal_id, row["candidate_digest"], target_state
            )
            action = f"promote_improvement:{target_state.value}"
            resource = self.promotion_resource(proposal_id)
            approval = connection.execute(
                """
                SELECT * FROM approvals
                WHERE approval_id = ? AND project_id = ? AND run_id = ?
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
                heldout_event, _ = self._verified_eval_event(connection, gate_eval)
                promotion_payload: dict[str, Any] = {
                    "from": current.value,
                    "to": target_state.value,
                    "approval_id": approval_id,
                    "promotion_record_id": str(uuid.uuid4()),
                    "candidate_id": proposal_id,
                    "candidate_digest": row["candidate_digest"],
                    "policy_version": self.policy_version,
                    "promotion_validation_eval_id": gate_eval.eval_id,
                    "promotion_validation_dataset_digest": gate_eval.dataset_digest,
                    "promotion_validation_attestation_digest": gate_eval.attestation_digest,
                    "promotion_validation_query_count": self._eval_dataset_use_count(
                        connection,
                        dataset_split="held_out",
                        dataset_digest=gate_eval.dataset_digest,
                        before_seq=None,
                    ),
                    "promotion_validation_status": gate_eval.status,
                    "approved_at": approval["decided_at"],
                    "evaluated_at": gate_eval.created_at,
                    "eval_event_seq": int(heldout_event["seq"]),
                }
            else:
                promotion_record = self._build_active_rule_promotion_record(
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
                event_type="improvement_promoted",
                actor=actor_id,
                command_id=str(uuid.uuid4()),
                correlation_id=row["source_run_id"],
                policy_version=self.policy_version,
                payload=promotion_payload,
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
