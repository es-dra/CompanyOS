"""Typed artifacts and evidence claims with anti-overclaiming guards."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .errors import AuthorizationError, EvidenceError, IntegrityError, NotFoundError
from .identity import IdentityManager, PrincipalRecord, Role, VerifiedPrincipal
from .store import SQLiteStore
from .types import (
    TERMINAL_TASK_STATES,
    EvidenceState,
    EvaluatorVerdict,
    TaskSpec,
    TaskState,
    canonical_json,
    utc_now,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLASSIFICATIONS = {"public", "publicable", "internal", "confidential", "secret"}
_FAKE_ENVIRONMENTS = {"fake", "synthetic", "test-double", "offline-simulation"}
_ARTIFACT_PRODUCER_ROLES = frozenset(
    {
        Role.WORKER,
        Role.SYSTEM,
        Role.PROVIDER_ATTESTOR,
        Role.HUMAN_ACCEPTOR,
        Role.BUSINESS_REVIEWER,
    }
)
_ARTIFACT_KIND_ROLES: dict[str, frozenset[Role]] = {
    "provider_receipt": frozenset({Role.PROVIDER_ATTESTOR}),
    "human_acceptance": frozenset({Role.HUMAN_ACCEPTOR}),
    "business_validation": frozenset({Role.BUSINESS_REVIEWER}),
    "heldout_eval": frozenset({Role.EVALUATOR}),
    "owner_approval": frozenset({Role.OWNER}),
    "rule_promotion_record": frozenset({Role.SYSTEM}),
}
_EVALUATOR_VERDICTS = frozenset(
    {EvaluatorVerdict.PASS, EvaluatorVerdict.PASS_WITH_RISK}
)
_STATE_VERIFIER_ROLES: dict[EvidenceState, Role] = {
    EvidenceState.PROVIDER_SMOKE: Role.PROVIDER_ATTESTOR,
    EvidenceState.HUMAN_ACCEPTANCE: Role.HUMAN_ACCEPTOR,
    EvidenceState.BUSINESS_VALIDATION: Role.BUSINESS_REVIEWER,
    EvidenceState.DURABLE_MEMORY_PROMOTION: Role.EVALUATOR,
    EvidenceState.ACTIVE_RULE_PROMOTION: Role.EVALUATOR,
}


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    project_id: str
    run_id: str
    task_id: str
    producer_principal_id: str
    kind: str
    uri: str
    content_digest: str
    confidentiality: str
    created_at: str


@dataclass(frozen=True)
class EvidenceClaim:
    evidence_id: str
    project_id: str
    run_id: str
    task_id: str
    claim: str
    evidence_state: EvidenceState
    artifact_refs: tuple[str, ...]
    verifier_principal_id: str
    verifier_version: str
    environment: str
    evaluator_verdict: EvaluatorVerdict
    non_claims: tuple[str, ...]
    created_at: str

    @property
    def verifier(self) -> str:
        """Backward-compatible alias whose value is always a principal ID."""

        return self.verifier_principal_id


@dataclass(frozen=True)
class EvidenceAssessment:
    task_id: str
    required_state: EvidenceState
    evaluator_required: bool
    matching_claim_ids: tuple[str, ...]
    satisfied: bool
    reasons: tuple[str, ...]


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty string")
    return value.strip()


def _digest(value: str) -> str:
    result = _text(value, "content_digest").lower()
    if not _SHA256.fullmatch(result):
        raise EvidenceError("content_digest must be a lowercase SHA-256 hex digest")
    return result


def _artifact(row: Mapping[str, Any]) -> ArtifactRecord:
    return ArtifactRecord(
        **{field: row[field] for field in ArtifactRecord.__dataclass_fields__}
    )


class EvidenceRegistry:
    """Persists evidence while keeping verification levels semantically distinct."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        identity: IdentityManager | None = None,
        policy_version: str = "companyos-policy-v1",
    ):
        self.store = store
        self.identity = identity or IdentityManager(store)
        self.policy_version = policy_version

    @staticmethod
    def _task_scope(connection: Any, task_id: str) -> Mapping[str, Any]:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"task not found: {task_id}")
        if row["run_id"] is None:
            raise EvidenceError(
                f"task has no run and cannot carry runtime evidence: {task_id}"
            )
        if TaskState(row["state"]) in TERMINAL_TASK_STATES:
            raise EvidenceError(
                f"terminal task is sealed against new evidence: {task_id}"
            )
        return row

    @staticmethod
    def _require_roles(
        principal: PrincipalRecord,
        required_roles: frozenset[Role],
        *,
        context: str,
    ) -> None:
        missing = required_roles - principal.roles
        if missing:
            rendered = ", ".join(sorted(role.value for role in missing))
            raise AuthorizationError(f"{context} requires role(s): {rendered}")

    @classmethod
    def _authorize_artifact_producer(
        cls, principal: PrincipalRecord, *, kind: str
    ) -> None:
        if not principal.roles.intersection(_ARTIFACT_PRODUCER_ROLES):
            allowed = ", ".join(sorted(role.value for role in _ARTIFACT_PRODUCER_ROLES))
            raise AuthorizationError(
                f"artifact production requires at least one producer role: {allowed}"
            )
        required = _ARTIFACT_KIND_ROLES.get(kind)
        if required:
            cls._require_roles(
                principal,
                required,
                context=f"{kind} artifact production",
            )

    def register_artifact(
        self,
        *,
        task_id: str,
        kind: str,
        uri: str,
        content_digest: str,
        producer_session: VerifiedPrincipal,
        confidentiality: str = "internal",
        artifact_id: str | None = None,
    ) -> ArtifactRecord:
        task_id = _text(task_id, "task_id")
        kind = _text(kind, "kind")
        uri = _text(uri, "uri")
        content_digest = _digest(content_digest)
        confidentiality = _text(confidentiality, "confidentiality").lower()
        if confidentiality not in _CLASSIFICATIONS:
            raise EvidenceError(f"unsupported confidentiality: {confidentiality}")
        artifact_id = _text(artifact_id or str(uuid.uuid4()), "artifact_id")

        with self.store.transaction(immediate=True) as connection:
            producer = self.identity.verify_in_transaction(connection, producer_session)
            self._authorize_artifact_producer(producer, kind=kind)
            existing = connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
            if existing is not None:
                record = _artifact(existing)
                expected = (
                    task_id,
                    producer.principal_id,
                    kind,
                    uri,
                    content_digest,
                    confidentiality,
                )
                actual = (
                    record.task_id,
                    record.producer_principal_id,
                    record.kind,
                    record.uri,
                    record.content_digest,
                    record.confidentiality,
                )
                if actual != expected:
                    raise IntegrityError(
                        f"artifact id reused with different content: {artifact_id}"
                    )
                return record
            task = self._task_scope(connection, task_id)
            now = utc_now()
            payload = {
                "kind": kind,
                "uri": uri,
                "content_digest": content_digest,
                "confidentiality": confidentiality,
                "producer_principal_id": producer.principal_id,
            }
            self.store.append_event(
                connection,
                aggregate_type="artifact",
                aggregate_id=artifact_id,
                expected_version=0,
                project_id=task["project_id"],
                run_id=task["run_id"],
                task_id=task_id,
                event_type="artifact_registered",
                actor=producer.principal_id,
                command_id=str(uuid.uuid4()),
                correlation_id=task["run_id"],
                policy_version=self.policy_version,
                payload=payload,
                confidentiality=confidentiality,
            )
            connection.execute(
                """
                INSERT INTO artifacts(
                    artifact_id, project_id, run_id, task_id,
                    producer_principal_id, kind, uri, content_digest,
                    confidentiality, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    task["project_id"],
                    task["run_id"],
                    task_id,
                    producer.principal_id,
                    kind,
                    uri,
                    content_digest,
                    confidentiality,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
            return _artifact(row)

    def record_claim(
        self,
        *,
        task_id: str,
        claim: str,
        evidence_state: EvidenceState | str,
        artifact_refs: Iterable[str],
        verifier_session: VerifiedPrincipal,
        verifier_version: str,
        environment: str,
        evaluator_verdict: EvaluatorVerdict | str,
        non_claims: Iterable[str] = (),
        evidence_id: str | None = None,
    ) -> EvidenceClaim:
        task_id = _text(task_id, "task_id")
        claim = _text(claim, "claim")
        try:
            state = EvidenceState.parse(str(evidence_state))
            verdict = EvaluatorVerdict(str(evaluator_verdict))
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc
        refs = tuple(
            dict.fromkeys(_text(item, "artifact_ref") for item in artifact_refs)
        )
        if not refs:
            raise EvidenceError(
                "an evidence claim must reference at least one artifact"
            )
        verifier_version = _text(verifier_version, "verifier_version")
        environment = _text(environment, "environment").lower()
        non_claim_values = tuple(_text(item, "non_claim") for item in non_claims)
        evidence_id = _text(evidence_id or str(uuid.uuid4()), "evidence_id")

        with self.store.transaction(immediate=True) as connection:
            verifier = self.identity.verify_in_transaction(connection, verifier_session)
            task = self._task_scope(connection, task_id)
            placeholders = ",".join("?" for _ in refs)
            rows = connection.execute(
                f"SELECT * FROM artifacts WHERE artifact_id IN ({placeholders})", refs
            ).fetchall()
            if len(rows) != len(refs):
                found = {row["artifact_id"] for row in rows}
                raise EvidenceError(
                    f"artifact references not found: {sorted(set(refs) - found)}"
                )
            if any(row["task_id"] != task_id for row in rows):
                raise EvidenceError("evidence artifacts must belong to the same task")
            self._enforce_provenance(
                state=state,
                environment=environment,
                verdict=verdict,
                verifier=verifier,
                artifacts=rows,
            )
            now = utc_now()
            payload = {
                "claim": claim,
                "evidence_state": state.value,
                "artifact_refs": list(refs),
                "verifier_principal_id": verifier.principal_id,
                "verifier_version": verifier_version,
                "environment": environment,
                "evaluator_verdict": verdict.value,
                "non_claims": list(non_claim_values),
            }
            self.store.append_event(
                connection,
                aggregate_type="evidence",
                aggregate_id=evidence_id,
                expected_version=0,
                project_id=task["project_id"],
                run_id=task["run_id"],
                task_id=task_id,
                event_type="evidence_claim_recorded",
                actor=verifier.principal_id,
                command_id=str(uuid.uuid4()),
                correlation_id=task["run_id"],
                policy_version=self.policy_version,
                payload=payload,
            )
            connection.execute(
                """
                INSERT INTO evidence_claims(
                    evidence_id, project_id, run_id, task_id, claim,
                    evidence_state, artifact_refs_json, verifier_principal_id,
                    verifier_version, environment, evaluator_verdict,
                    non_claims_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    task["project_id"],
                    task["run_id"],
                    task_id,
                    claim,
                    state.value,
                    canonical_json(list(refs)),
                    verifier.principal_id,
                    verifier_version,
                    environment,
                    verdict.value,
                    canonical_json(list(non_claim_values)),
                    now,
                ),
            )
        return EvidenceClaim(
            evidence_id=evidence_id,
            project_id=task["project_id"],
            run_id=task["run_id"],
            task_id=task_id,
            claim=claim,
            evidence_state=state,
            artifact_refs=refs,
            verifier_principal_id=verifier.principal_id,
            verifier_version=verifier_version,
            environment=environment,
            evaluator_verdict=verdict,
            non_claims=non_claim_values,
            created_at=now,
        )

    @classmethod
    def _enforce_provenance(
        cls,
        *,
        state: EvidenceState,
        environment: str,
        verdict: EvaluatorVerdict,
        verifier: PrincipalRecord,
        artifacts: Iterable[Mapping[str, Any]],
    ) -> None:
        artifact_rows = tuple(artifacts)
        artifact_kinds = {str(row["kind"]) for row in artifact_rows}
        producer_ids = {str(row["producer_principal_id"]) for row in artifact_rows}
        if environment in _FAKE_ENVIRONMENTS and state not in {
            EvidenceState.STRUCTURE,
            EvidenceState.RUNTIME,
        }:
            raise EvidenceError(
                f"{environment} evidence can prove only structure/runtime verification, not {state.value}"
            )

        required_role = _STATE_VERIFIER_ROLES.get(state)
        if required_role is not None:
            cls._require_roles(
                verifier,
                frozenset({required_role}),
                context=f"{state.value} verification",
            )

        independent_evaluator_required = verdict in _EVALUATOR_VERDICTS or state in {
            EvidenceState.DURABLE_MEMORY_PROMOTION,
            EvidenceState.ACTIVE_RULE_PROMOTION,
        }
        if verdict in _EVALUATOR_VERDICTS:
            cls._require_roles(
                verifier,
                frozenset({Role.EVALUATOR}),
                context=f"{verdict.value} evaluator verdict",
            )
        if independent_evaluator_required and verifier.principal_id in producer_ids:
            raise AuthorizationError(
                "an independent evaluator cannot verify an artifact it produced"
            )

        if state is EvidenceState.PROVIDER_SMOKE:
            if "provider_receipt" not in artifact_kinds:
                raise EvidenceError(
                    "provider_smoke requires a provider_receipt artifact"
                )
        if (
            state is EvidenceState.HUMAN_ACCEPTANCE
            and "human_acceptance" not in artifact_kinds
        ):
            raise EvidenceError("human_acceptance requires a human_acceptance artifact")
        if (
            state is EvidenceState.BUSINESS_VALIDATION
            and "business_validation" not in artifact_kinds
        ):
            raise EvidenceError(
                "business_validation requires a business_validation artifact"
            )
        if state is EvidenceState.ACTIVE_RULE_PROMOTION and (
            not {"heldout_eval", "owner_approval", "rule_promotion_record"}
            <= artifact_kinds
        ):
            raise EvidenceError(
                "active_rule_promotion requires independent evaluator verification "
                "plus heldout_eval, owner_approval, and rule_promotion_record artifacts"
            )

    def assess_task(self, task_id: str) -> EvidenceAssessment:
        rows = self.store.query("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
        if not rows:
            raise NotFoundError(f"task not found: {task_id}")
        spec = TaskSpec.from_dict(json.loads(rows[0]["spec_json"]))
        claims = self.store.query(
            "SELECT evidence_id, evaluator_verdict FROM evidence_claims "
            "WHERE task_id = ? AND evidence_state = ? ORDER BY created_at",
            (task_id, spec.evidence_target.value),
        )
        passing = [
            row["evidence_id"]
            for row in claims
            if row["evaluator_verdict"]
            in {
                EvaluatorVerdict.PASS.value,
                EvaluatorVerdict.PASS_WITH_RISK.value,
                EvaluatorVerdict.NOT_REQUIRED.value,
            }
        ]
        reasons: list[str] = []
        if not passing:
            reasons.append(f"no passing {spec.evidence_target.value} claim")
        if spec.evaluator_required and not any(
            row["evaluator_verdict"]
            in {
                EvaluatorVerdict.PASS.value,
                EvaluatorVerdict.PASS_WITH_RISK.value,
            }
            for row in claims
        ):
            reasons.append("independent evaluator verdict is required")
        return EvidenceAssessment(
            task_id=task_id,
            required_state=spec.evidence_target,
            evaluator_required=spec.evaluator_required,
            matching_claim_ids=tuple(passing),
            satisfied=not reasons,
            reasons=tuple(reasons),
        )

    def require_task_evidence(self, task_id: str) -> EvidenceAssessment:
        assessment = self.assess_task(task_id)
        if not assessment.satisfied:
            raise EvidenceError(
                f"task evidence is not satisfied: {task_id}: {', '.join(assessment.reasons)}"
            )
        return assessment
