"""Evidence-backed memory candidates with explicit human/eval promotion gates."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .context import KNOWN_CLASSIFICATIONS
from .errors import (
    AuthorizationError,
    ContractError,
    EvidenceError,
    IntegrityError,
    NotFoundError,
)
from .identity import IdentityManager, Role, VerifiedPrincipal
from .scope import normalize_scope, scope_allowed
from .store import SQLiteStore
from .types import TaskSpec, content_hash, utc_now


MEMORY_PROMOTION_CAPABILITY = "durable_memory_promotion"
MEMORY_PROMOTION_ACTION = "promote_memory"
MEMORY_TRANSITIONS = {"candidate": "limited", "limited": "active"}
CLASSIFICATION_RANK = {
    "public": 0,
    "publicable": 0,
    "internal": 1,
    "private": 2,
    "confidential": 2,
    "secret": 3,
}


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")
    return value.strip()


def _datetime(value: str | datetime, name: str) -> datetime:
    try:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
    except ValueError as exc:
        raise ContractError(f"{name} must be an ISO-8601 timestamp") from exc
    if not isinstance(parsed, datetime) or parsed.tzinfo is None:
        raise ContractError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _candidate_digest(row: dict[str, Any]) -> str:
    immutable = {
        key: row[key]
        for key in (
            "memory_id",
            "project_id",
            "source_evidence_id",
            "source_digest",
            "scope",
            "classification",
            "content",
            "effective_at",
            "expires_at",
            "supersedes",
            "created_at",
        )
    }
    return content_hash(immutable)


def _evidence_provenance(connection: Any, evidence: Any) -> tuple[str, list[Any]]:
    try:
        artifact_refs = json.loads(evidence["artifact_refs_json"])
    except json.JSONDecodeError as exc:
        raise IntegrityError("source evidence artifact_refs_json is invalid") from exc
    if (
        not isinstance(artifact_refs, list)
        or not artifact_refs
        or not all(isinstance(item, str) and item for item in artifact_refs)
        or len(artifact_refs) != len(set(artifact_refs))
    ):
        raise EvidenceError("source evidence must reference unique artifact IDs")
    placeholders = ",".join("?" for _ in artifact_refs)
    artifact_rows = list(
        connection.execute(
            f"SELECT * FROM artifacts WHERE artifact_id IN ({placeholders})",
            tuple(artifact_refs),
        ).fetchall()
    )
    found = {row["artifact_id"] for row in artifact_rows}
    missing = sorted(set(artifact_refs) - found)
    if missing:
        raise EvidenceError(f"source evidence artifacts do not exist: {missing}")
    artifact_payload = [
        {
            "artifact_id": row["artifact_id"],
            "kind": row["kind"],
            "uri": row["uri"],
            "content_digest": row["content_digest"],
            "confidentiality": row["confidentiality"],
            "producer_principal_id": row["producer_principal_id"],
        }
        for row in sorted(artifact_rows, key=lambda item: item["artifact_id"])
    ]
    evidence_payload = {
        key: evidence[key]
        for key in (
            "evidence_id",
            "project_id",
            "run_id",
            "task_id",
            "claim",
            "evidence_state",
            "artifact_refs_json",
            "verifier_principal_id",
            "verifier_version",
            "environment",
            "evaluator_verdict",
            "non_claims_json",
            "created_at",
        )
    }
    evidence_payload["artifacts"] = artifact_payload
    return content_hash(evidence_payload), artifact_rows


def _promotion_request(row: dict[str, Any], target_status: str) -> dict[str, Any]:
    target_status = _text(target_status, "target_status").lower()
    expected = MEMORY_TRANSITIONS.get(row["status"])
    if target_status != expected:
        raise ContractError(
            f"memory promotion must follow candidate -> limited -> active; "
            f"{row['status']} -> {target_status} is not allowed"
        )
    candidate_digest = _candidate_digest(row)
    request = {
        "memory_id": row["memory_id"],
        "candidate_digest": candidate_digest,
        "from_status": row["status"],
        "target_status": target_status,
        "capability": MEMORY_PROMOTION_CAPABILITY,
        "action": MEMORY_PROMOTION_ACTION,
        "resource": f"memory://{row['memory_id']}",
    }
    return {**request, "request_digest": content_hash(request)}


class MemoryRegistry:
    """Create memory candidates from evidence and promote only through exact gates."""

    def __init__(self, store: SQLiteStore, *, identity: IdentityManager | None = None):
        self.store = store
        self.identity = identity or IdentityManager(store)

    def create_candidate(
        self,
        *,
        memory_id: str,
        project_id: str,
        source_evidence_id: str,
        scope: str,
        classification: str,
        content: str,
        ttl_seconds: int = 30 * 24 * 60 * 60,
        effective_at: str | datetime | None = None,
        expires_at: str | datetime | None = None,
        supersedes: str | None = None,
        actor: VerifiedPrincipal,
        policy_version: str = "1",
    ) -> dict[str, Any]:
        memory_id = _text(memory_id, "memory_id")
        project_id = _text(project_id, "project_id")
        source_evidence_id = _text(source_evidence_id, "source_evidence_id")
        scope = normalize_scope(_text(scope, "scope"))
        classification = _text(classification, "classification").lower()
        content = _text(content, "content")
        if classification not in KNOWN_CLASSIFICATIONS:
            raise ContractError(f"unsupported classification: {classification}")
        if supersedes is not None:
            supersedes = _text(supersedes, "supersedes")
            if supersedes == memory_id:
                raise ContractError("a memory item cannot supersede itself")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds < 1
        ):
            raise ContractError("ttl_seconds must be a positive integer")
        if expires_at is not None and ttl_seconds != 30 * 24 * 60 * 60:
            raise ContractError(
                "provide either expires_at or a non-default ttl_seconds, not both"
            )

        created = _datetime(utc_now(), "created_at")
        effective = (
            _datetime(effective_at, "effective_at")
            if effective_at is not None
            else created
        )
        expiry = (
            _datetime(expires_at, "expires_at")
            if expires_at is not None
            else effective + timedelta(seconds=ttl_seconds)
        )
        if expiry <= effective:
            raise ContractError("memory expiry must be later than effective_at")

        with self.store.transaction(immediate=True) as connection:
            actor_record = self.identity.verify_in_transaction(connection, actor)
            if not actor_record.roles.intersection(
                {Role.WORKER, Role.EVALUATOR, Role.SYSTEM}
            ):
                raise AuthorizationError(
                    "memory candidate actor requires worker, evaluator, or system role"
                )
            actor_id = actor_record.principal_id
            existing = connection.execute(
                "SELECT * FROM memory_items WHERE memory_id = ?", (memory_id,)
            ).fetchone()
            if existing is not None:
                current = dict(existing)
                if (
                    current["project_id"] == project_id
                    and current["source_evidence_id"] == source_evidence_id
                    and current["scope"] == scope
                    and current["classification"] == classification
                    and current["content"] == content
                    and current["supersedes"] == supersedes
                ):
                    return {**current, "candidate_digest": _candidate_digest(current)}
                raise IntegrityError(
                    f"memory_id already exists with different content: {memory_id}"
                )

            evidence = connection.execute(
                """
                SELECT e.*, t.goal_id, t.spec_json
                FROM evidence_claims e
                JOIN tasks t ON t.task_id = e.task_id
                WHERE e.evidence_id = ?
                """,
                (source_evidence_id,),
            ).fetchone()
            if evidence is None:
                raise NotFoundError(
                    f"source evidence does not exist: {source_evidence_id}"
                )
            if evidence["project_id"] != project_id:
                raise ContractError("memory project must match source evidence project")
            try:
                task_spec = TaskSpec.from_dict(json.loads(evidence["spec_json"]))
            except Exception as exc:
                raise ContractError(
                    "source task has no valid compiled memory authority"
                ) from exc
            if not scope_allowed(task_spec.write_scope, scope):
                raise AuthorizationError(
                    "memory scope exceeds source TaskSpec write_scope"
                )
            if evidence["evaluator_verdict"] not in {
                "not_required",
                "pass",
                "pass_with_residual_risk",
            }:
                raise EvidenceError(
                    "failed or pending evidence cannot seed a promotable memory"
                )
            source_digest, artifact_rows = _evidence_provenance(connection, evidence)
            required_rank = max(
                (
                    CLASSIFICATION_RANK.get(row["confidentiality"], 3)
                    for row in artifact_rows
                ),
                default=0,
            )
            if CLASSIFICATION_RANK[classification] < required_rank:
                raise ContractError(
                    "memory classification cannot be less restrictive than its evidence artifacts"
                )
            if supersedes is not None:
                previous = connection.execute(
                    "SELECT project_id, scope FROM memory_items WHERE memory_id = ?",
                    (supersedes,),
                ).fetchone()
                if previous is None:
                    raise NotFoundError(
                        f"superseded memory does not exist: {supersedes}"
                    )
                if previous["project_id"] != project_id or previous["scope"] != scope:
                    raise ContractError(
                        "memory supersession requires the same project and scope"
                    )

            record = {
                "memory_id": memory_id,
                "project_id": project_id,
                "source_evidence_id": source_evidence_id,
                "source_digest": source_digest,
                "scope": scope,
                "classification": classification,
                "content": content,
                "status": "candidate",
                "effective_at": _iso(effective),
                "expires_at": _iso(expiry),
                "supersedes": supersedes,
                "promotion_approval_id": None,
                "heldout_eval_id": None,
                "created_at": _iso(created),
            }
            event = self.store.append_event(
                connection,
                aggregate_type="memory_item",
                aggregate_id=memory_id,
                expected_version=0,
                project_id=project_id,
                run_id=evidence["run_id"],
                task_id=evidence["task_id"],
                event_type="memory_candidate_created",
                actor=actor_id,
                command_id=str(uuid.uuid4()),
                correlation_id=evidence["run_id"],
                policy_version=_text(policy_version, "policy_version"),
                confidentiality=classification,
                payload={
                    key: value for key, value in record.items() if key != "content"
                },
            )
            connection.execute(
                """
                INSERT INTO memory_items(
                    memory_id, project_id, source_evidence_id, source_digest,
                    scope, classification, content, status, effective_at,
                    expires_at, supersedes, promotion_approval_id,
                    heldout_eval_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(record.values()),
            )
        return {
            **record,
            "candidate_digest": _candidate_digest(record),
            "event_id": event["event_id"],
        }

    def promotion_request(self, memory_id: str, target_status: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM memory_items WHERE memory_id = ?",
            (_text(memory_id, "memory_id"),),
        )
        if not rows:
            raise NotFoundError(f"memory does not exist: {memory_id}")
        return _promotion_request(rows[0], target_status)

    def promote(
        self,
        *,
        memory_id: str,
        target_status: str,
        approval_id: str,
        heldout_eval_id: str,
        human_approver: VerifiedPrincipal,
        policy_version: str = "1",
    ) -> dict[str, Any]:
        memory_id = _text(memory_id, "memory_id")
        approval_id = _text(approval_id, "approval_id")
        heldout_eval_id = _text(heldout_eval_id, "heldout_eval_id")
        now = _datetime(utc_now(), "now")

        with self.store.transaction(immediate=True) as connection:
            human_approver_id = self.identity.require_role_in_transaction(
                connection, human_approver, Role.OWNER
            ).principal_id
            row = connection.execute(
                "SELECT * FROM memory_items WHERE memory_id = ?", (memory_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"memory does not exist: {memory_id}")
            memory = dict(row)
            if _datetime(memory["expires_at"], "memory.expires_at") <= now:
                raise EvidenceError("expired memory candidates cannot be promoted")
            request = _promotion_request(memory, target_status)
            evidence = connection.execute(
                """
                SELECT e.*, t.goal_id
                FROM evidence_claims e
                JOIN tasks t ON t.task_id = e.task_id
                WHERE e.evidence_id = ?
                """,
                (memory["source_evidence_id"],),
            ).fetchone()
            if evidence is None:
                raise EvidenceError("memory provenance evidence is no longer available")
            if evidence["evaluator_verdict"] not in {
                "not_required",
                "pass",
                "pass_with_residual_risk",
            }:
                raise EvidenceError("memory provenance evidence is no longer passing")
            current_source_digest, _ = _evidence_provenance(connection, evidence)
            if current_source_digest != memory["source_digest"]:
                raise EvidenceError(
                    "memory provenance changed after candidate creation"
                )

            approval = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if approval is None:
                raise AuthorizationError(
                    f"promotion approval does not exist: {approval_id}"
                )
            exact_approval = (
                approval["project_id"] == memory["project_id"]
                and approval["goal_id"] == evidence["goal_id"]
                and approval["run_id"] == evidence["run_id"]
                and approval["task_id"] == evidence["task_id"]
                and approval["capability"] == MEMORY_PROMOTION_CAPABILITY
                and approval["action"] == MEMORY_PROMOTION_ACTION
                and approval["resource"] == request["resource"]
                and approval["request_digest"] == request["request_digest"]
                and approval["decision"] == "approved"
                and approval["approver"] == human_approver_id
                and approval["decided_at"] is not None
                and approval["expires_at"] is not None
            )
            if not exact_approval:
                raise AuthorizationError(
                    "approval does not exactly authorize this memory promotion"
                )
            approval_expiry = _datetime(approval["expires_at"], "approval.expires_at")
            decided_at = _datetime(approval["decided_at"], "approval.decided_at")
            if approval_expiry <= now:
                raise AuthorizationError("memory promotion approval has expired")

            evaluation = connection.execute(
                "SELECT * FROM eval_runs WHERE eval_id = ?", (heldout_eval_id,)
            ).fetchone()
            if evaluation is None:
                raise EvidenceError(
                    f"held-out evaluation does not exist: {heldout_eval_id}"
                )
            try:
                safety_failures = json.loads(evaluation["safety_failures_json"])
            except json.JSONDecodeError as exc:
                raise EvidenceError(
                    "held-out evaluation safety failures are invalid JSON"
                ) from exc
            if (
                evaluation["project_id"] != memory["project_id"]
                or evaluation["candidate_digest"] != request["candidate_digest"]
                or evaluation["dataset_split"] != "held_out"
                or evaluation["status"] != "pass"
                or not isinstance(safety_failures, list)
                or safety_failures
            ):
                raise EvidenceError(
                    "promotion requires a matching passing held-out eval with no safety failures"
                )
            if memory["status"] == "limited":
                if memory["heldout_eval_id"] == heldout_eval_id:
                    raise EvidenceError(
                        "active memory promotion requires new post-limited evaluation evidence"
                    )
                prior_eval = connection.execute(
                    "SELECT dataset_digest FROM eval_runs WHERE eval_id = ?",
                    (memory["heldout_eval_id"],),
                ).fetchone()
                if (
                    prior_eval is not None
                    and prior_eval["dataset_digest"] == evaluation["dataset_digest"]
                ):
                    raise EvidenceError(
                        "active memory promotion requires a fresh validation dataset"
                    )
                limited_event = connection.execute(
                    "SELECT occurred_at FROM events WHERE aggregate_type = 'memory_item' "
                    "AND aggregate_id = ? AND event_type = 'memory_promoted' "
                    "ORDER BY aggregate_version DESC LIMIT 1",
                    (memory_id,),
                ).fetchone()
                if limited_event is None or _datetime(
                    evaluation["created_at"], "eval.created_at"
                ) <= _datetime(limited_event["occurred_at"], "limited.occurred_at"):
                    raise EvidenceError(
                        "active memory promotion requires evaluation after limited rollout"
                    )
            if _datetime(evaluation["created_at"], "eval.created_at") > decided_at:
                raise AuthorizationError(
                    "human approval must be decided after the held-out evaluation"
                )

            connection.execute(
                "UPDATE memory_items SET status = ?, promotion_approval_id = ?, heldout_eval_id = ? "
                "WHERE memory_id = ?",
                (request["target_status"], approval_id, heldout_eval_id, memory_id),
            )
            event_head = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) AS version FROM events "
                "WHERE aggregate_type = 'memory_item' AND aggregate_id = ?",
                (memory_id,),
            ).fetchone()
            event = self.store.append_event(
                connection,
                aggregate_type="memory_item",
                aggregate_id=memory_id,
                expected_version=int(event_head["version"]),
                project_id=memory["project_id"],
                run_id=evidence["run_id"],
                task_id=evidence["task_id"],
                event_type="memory_promoted",
                actor=human_approver_id,
                command_id=str(uuid.uuid4()),
                correlation_id=evidence["run_id"],
                policy_version=_text(policy_version, "policy_version"),
                confidentiality=memory["classification"],
                payload={
                    "memory_id": memory_id,
                    "from_status": request["from_status"],
                    "target_status": request["target_status"],
                    "candidate_digest": request["candidate_digest"],
                    "approval_id": approval_id,
                    "heldout_eval_id": heldout_eval_id,
                },
            )
            promoted = dict(
                connection.execute(
                    "SELECT * FROM memory_items WHERE memory_id = ?", (memory_id,)
                ).fetchone()
            )
        return {
            **promoted,
            "candidate_digest": request["candidate_digest"],
            "event_id": event["event_id"],
        }

    def get(self, memory_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM memory_items WHERE memory_id = ?",
            (_text(memory_id, "memory_id"),),
        )
        if not rows:
            raise NotFoundError(f"memory does not exist: {memory_id}")
        return {**rows[0], "candidate_digest": _candidate_digest(rows[0])}
