"""Durable outbox workflow with task grants, fencing, and crash recovery."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from .errors import (
    AuthorizationError,
    ContractError,
    IntegrityError,
    NotFoundError,
    SimulatedCrash,
)
from .fake_provider import FakeProvider, FakeProviderReceipt
from .identity import IdentityManager, Role, VerifiedPrincipal
from .policy import PolicyEngine
from .store import SQLiteStore
from .types import (
    Capability,
    LoopState,
    TaskSpec,
    TaskState,
    canonical_json,
    content_hash,
    utc_now,
)


_FAULTS = {None, "before_effect", "after_effect_before_checkpoint", "after_checkpoint"}
_STEP_FIELDS = frozenset({"step_id", "adapter", "action", "resource", "request_digest"})
_ENVELOPE_FIELDS = frozenset(
    {"request", "grant_id", "principal", "capability", "action", "resource", "fence"}
)


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value.strip()


def _declared_step(spec: TaskSpec, step_id: str) -> Mapping[str, Any]:
    """Return one fully bound executable step or fail closed.

    ``workflow_steps`` contains executable effects only; planning prose belongs
    in the authoring packet and never becomes runtime authority.
    """

    matches = [step for step in spec.workflow_steps if step.get("step_id") == step_id]
    if len(matches) != 1:
        raise ContractError(
            f"workflow step is not declared exactly once in TaskSpec: {step_id}"
        )
    step = matches[0]
    if set(step) != _STEP_FIELDS:
        missing = sorted(_STEP_FIELDS - set(step))
        unknown = sorted(set(step) - _STEP_FIELDS)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ContractError(
            "executable workflow step must contain only the exact binding fields"
            + (f": {', '.join(details)}" if details else "")
        )
    for field in ("step_id", "adapter", "action", "resource", "request_digest"):
        _text(step[field], f"workflow_step.{field}")
    return step


def _assert_step_binding(
    spec: TaskSpec,
    *,
    step_id: str,
    adapter: str,
    action: str,
    resource: str,
    request_digest: str,
) -> None:
    declared = _declared_step(spec, step_id)
    actual = {
        "step_id": step_id,
        "adapter": adapter,
        "action": action,
        "resource": resource,
        "request_digest": request_digest,
    }
    mismatches = sorted(
        field for field in _STEP_FIELDS if declared[field] != actual[field]
    )
    if mismatches:
        raise ContractError(
            "effect does not match exact TaskSpec workflow step binding: "
            + ", ".join(mismatches)
        )


def _effect_envelope(effect: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        envelope = json.loads(effect["request_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IntegrityError("outbox authority envelope is invalid") from exc
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise IntegrityError("outbox authority envelope has an invalid shape")
    request = envelope.get("request")
    if not isinstance(request, dict):
        raise IntegrityError("outbox request must be an object")
    if content_hash(request) != effect["request_digest"]:
        raise IntegrityError("outbox request digest mismatch")
    return envelope


def _assert_effect_lifecycle(connection: Any, task: Mapping[str, Any]) -> None:
    try:
        task_state = TaskState(task["state"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationError("effect task lifecycle projection is invalid") from exc
    run = connection.execute(
        "SELECT project_id, goal_id, loop_state FROM runs WHERE run_id = ?",
        (task["run_id"],),
    ).fetchone()
    if (
        run is None
        or run["project_id"] != task["project_id"]
        or run["goal_id"] != task["goal_id"]
        or run["loop_state"] != LoopState.RUNNING.value
    ):
        raise AuthorizationError("effect parent run is not executable")
    if task_state is not TaskState.RUNNING:
        raise AuthorizationError(f"effect task is not running: {task_state.value}")


@dataclass(frozen=True)
class OutboxEffect:
    """Canonical public OutboxEffect wire DTO."""

    effect_id: str
    project_id: str
    run_id: str
    task_id: str
    step_id: str
    adapter: str
    idempotency_key: str
    request_digest: str
    status: str
    created_at: str
    dispatched_at: str | None = None
    reconciled_at: str | None = None
    last_error: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "step_id": self.step_id,
            "adapter": self.adapter,
            "idempotency_key": self.idempotency_key,
            "request_digest": self.request_digest,
            "status": self.status,
            "created_at": self.created_at,
            "dispatched_at": self.dispatched_at,
            "reconciled_at": self.reconciled_at,
            "last_error": self.last_error,
        }


@dataclass(frozen=True)
class EnqueueEffectResult(OutboxEffect):
    """Enqueue result with non-wire idempotency metadata."""

    replayed: bool = False


@dataclass(frozen=True)
class EffectReceipt:
    """Canonical public EffectReceipt wire DTO."""

    receipt_id: str
    effect_id: str
    status: str
    result: Mapping[str, Any]
    result_digest: str
    recorded_at: str
    provider_receipt: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "effect_id": self.effect_id,
            "status": self.status,
            "provider_receipt": self.provider_receipt,
            "result": dict(self.result),
            "result_digest": self.result_digest,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True)
class DispatchResult:
    effect_id: str
    status: str
    provider_receipt: str | None
    result: Mapping[str, Any]
    provider_replayed: bool
    checkpoint_replayed: bool


def _outbox_values(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "effect_id": row["effect_id"],
        "project_id": row["project_id"],
        "run_id": row["run_id"],
        "task_id": row["task_id"],
        "step_id": row["step_id"],
        "adapter": row["adapter"],
        "idempotency_key": row["idempotency_key"],
        "request_digest": row["request_digest"],
        "status": row["status"],
        "created_at": row["created_at"],
        "dispatched_at": row["dispatched_at"],
        "reconciled_at": row["reconciled_at"],
        "last_error": row["last_error"],
    }


def _effect_receipt(row: Mapping[str, Any]) -> EffectReceipt:
    return EffectReceipt(
        receipt_id=row["receipt_id"],
        effect_id=row["effect_id"],
        status=row["status"],
        provider_receipt=row["provider_receipt"],
        result=json.loads(row["result_json"]),
        result_digest=row["result_digest"],
        recorded_at=row["recorded_at"],
    )


class DurableWorkflow:
    def __init__(
        self,
        store: SQLiteStore,
        provider: FakeProvider,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
    ):
        self.store = store
        self.provider = provider
        self.identity = identity or IdentityManager(store)
        self.policy = PolicyEngine(store, identity=self.identity)
        self.policy_version = policy_version

    def initialize(self) -> None:
        self.store.initialize()
        self.provider.initialize()

    def enqueue(
        self,
        *,
        task_id: str,
        step_id: str,
        adapter: str,
        idempotency_key: str,
        request: Mapping[str, Any],
        grant_id: str,
        principal: VerifiedPrincipal,
        capability: Capability | str,
        action: str,
        resource: str,
        fence: int | None,
        effect_id: str | None = None,
    ) -> EnqueueEffectResult:
        task_id = _text(task_id, "task_id")
        step_id = _text(step_id, "step_id")
        adapter = _text(adapter, "adapter")
        idempotency_key = _text(idempotency_key, "idempotency_key")
        grant_id = _text(grant_id, "grant_id")
        action = _text(action, "action")
        resource = _text(resource, "resource")
        if not isinstance(request, Mapping):
            raise ContractError("request must be an object")
        try:
            capability_value = Capability(str(capability))
        except ValueError as exc:
            raise ContractError(f"unsupported capability: {capability}") from exc
        if fence is not None and (
            isinstance(fence, bool) or not isinstance(fence, int) or fence < 1
        ):
            raise ContractError("fence must be a positive integer or null")
        effect_id = _text(effect_id or str(uuid.uuid4()), "effect_id")
        request_dict = dict(request)
        request_digest = content_hash(request_dict)

        with self.store.transaction(immediate=True) as connection:
            principal_record = self.identity.verify_in_transaction(
                connection, principal
            )
            if not principal_record.roles.intersection({Role.WORKER, Role.SYSTEM}):
                raise ContractError("effect enqueuer requires worker or system role")
            principal_id = principal_record.principal_id
            envelope = {
                "request": request_dict,
                "grant_id": grant_id,
                "principal": principal_id,
                "capability": capability_value.value,
                "action": action,
                "resource": resource,
                "fence": fence,
            }
            task = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if task is None or task["run_id"] is None:
                raise NotFoundError(f"runnable task not found: {task_id}")
            _assert_effect_lifecycle(connection, task)
            spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
            if capability_value not in spec.capabilities:
                raise ContractError(
                    f"task contract does not allow capability {capability_value.value}: {task_id}"
                )
            _assert_step_binding(
                spec,
                step_id=step_id,
                adapter=adapter,
                action=action,
                resource=resource,
                request_digest=request_digest,
            )
            prior = connection.execute(
                "SELECT * FROM outbox WHERE project_id = ? AND idempotency_key = ?",
                (task["project_id"], idempotency_key),
            ).fetchone()
            if prior is not None:
                stored = json.loads(prior["request_json"])
                expected = (task_id, step_id, adapter, request_digest, envelope)
                actual = (
                    prior["task_id"],
                    prior["step_id"],
                    prior["adapter"],
                    prior["request_digest"],
                    stored,
                )
                if actual != expected:
                    raise IntegrityError(
                        "outbox idempotency key reused with different request or authority"
                    )
                return EnqueueEffectResult(**_outbox_values(prior), replayed=True)
            self.policy.preflight_effect_authority(
                connection,
                grant_id=grant_id,
                project_id=task["project_id"],
                goal_id=task["goal_id"],
                run_id=task["run_id"],
                task_id=task_id,
                principal=principal,
                capability=capability_value,
                action=action,
                resource=resource,
                request_digest=request_digest,
                policy_version=self.policy_version,
                fence=fence,
            )
            step = connection.execute(
                "SELECT * FROM workflow_steps WHERE task_id = ? AND step_id = ?",
                (task_id, step_id),
            ).fetchone()
            if step is not None:
                raise IntegrityError(
                    "workflow step is already bound to another outbox effect"
                )
            self.store.append_event(
                connection,
                aggregate_type="effect",
                aggregate_id=effect_id,
                expected_version=0,
                project_id=task["project_id"],
                run_id=task["run_id"],
                task_id=task_id,
                event_type="effect_enqueued",
                actor=principal_id,
                auth_context={
                    "session_id": principal.session_id,
                    "authenticated_role": sorted(
                        role.value for role in principal_record.roles
                    )[0],
                },
                command_id=str(uuid.uuid4()),
                correlation_id=task["run_id"],
                policy_version=self.policy_version,
                payload={
                    "step_id": step_id,
                    "adapter": adapter,
                    "request_digest": request_digest,
                    "capability": capability_value.value,
                    "resource": resource,
                },
                idempotency_key=idempotency_key,
            )
            now = utc_now()
            connection.execute(
                """
                INSERT INTO outbox(
                    effect_id, project_id, run_id, task_id, step_id, adapter,
                    idempotency_key, request_digest, request_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'authorization_pending', ?)
                """,
                (
                    effect_id,
                    task["project_id"],
                    task["run_id"],
                    task_id,
                    step_id,
                    adapter,
                    idempotency_key,
                    request_digest,
                    canonical_json(envelope),
                    now,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO workflow_steps(
                    task_id, step_id, status, input_digest, effect_id, started_at
                ) VALUES (?, ?, 'queued', ?, ?, ?)
                """,
                (task_id, step_id, request_digest, effect_id, now),
            )
            return EnqueueEffectResult(
                effect_id=effect_id,
                project_id=task["project_id"],
                run_id=task["run_id"],
                task_id=task_id,
                step_id=step_id,
                adapter=adapter,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                status="authorization_pending",
                created_at=now,
            )

    def get_effect(self, effect_id: str) -> OutboxEffect:
        """Return one persisted effect as the canonical public wire DTO."""

        effect_id = _text(effect_id, "effect_id")
        rows = self.store.query(
            "SELECT * FROM outbox WHERE effect_id = ?", (effect_id,)
        )
        if not rows:
            raise NotFoundError(f"outbox effect not found: {effect_id}")
        return OutboxEffect(**_outbox_values(rows[0]))

    def get_receipt(self, effect_id: str) -> EffectReceipt | None:
        """Return the canonical receipt DTO when reconciliation is durable."""

        effect_id = _text(effect_id, "effect_id")
        rows = self.store.query(
            "SELECT * FROM effect_receipts WHERE effect_id = ?", (effect_id,)
        )
        return _effect_receipt(rows[0]) if rows else None

    def _assert_persisted_step_binding(
        self, effect: Mapping[str, Any], envelope: Mapping[str, Any]
    ) -> None:
        rows = self.store.query(
            "SELECT project_id, run_id, spec_json FROM tasks WHERE task_id = ?",
            (effect["task_id"],),
        )
        if not rows:
            raise IntegrityError(
                f"outbox effect references a missing task: {effect['task_id']}"
            )
        task = rows[0]
        if (
            task["project_id"] != effect["project_id"]
            or task["run_id"] != effect["run_id"]
        ):
            raise IntegrityError("outbox effect task identity mismatch")
        spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
        _assert_step_binding(
            spec,
            step_id=effect["step_id"],
            adapter=effect["adapter"],
            action=envelope["action"],
            resource=envelope["resource"],
            request_digest=effect["request_digest"],
        )

    def dispatch(
        self, effect_id: str, *, fault_at: str | None = None
    ) -> DispatchResult:
        effect_id = _text(effect_id, "effect_id")
        if fault_at not in _FAULTS:
            raise ContractError(f"unsupported fault point: {fault_at}")
        rows = self.store.query(
            "SELECT * FROM outbox WHERE effect_id = ?", (effect_id,)
        )
        if not rows:
            raise NotFoundError(f"outbox effect not found: {effect_id}")
        effect = rows[0]
        existing = self.store.query(
            "SELECT * FROM effect_receipts WHERE effect_id = ?", (effect_id,)
        )
        if existing:
            receipt = _effect_receipt(existing[0])
            return DispatchResult(
                effect_id=effect_id,
                status=receipt.status,
                provider_receipt=receipt.provider_receipt,
                result=dict(receipt.result),
                provider_replayed=receipt.provider_receipt is not None,
                checkpoint_replayed=True,
            )
        envelope = _effect_envelope(effect)
        # Reconcile a receipt that already exists before revalidating current
        # authority. This branch performs no new external action; refusing the
        # checkpoint would lose a committed side effect after a crash.
        provider_receipt = self.provider.lookup(
            project_id=effect["project_id"],
            idempotency_key=effect["idempotency_key"],
            effect_id=effect_id,
            request_digest=effect["request_digest"],
        )
        if provider_receipt is not None:
            return self._checkpoint(effect, provider_receipt)
        self._assert_persisted_step_binding(effect, envelope)
        self.policy._consume_effect(effect_id)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE outbox SET status = 'ready' WHERE effect_id = ? AND status = 'authorization_pending'",
                (effect_id,),
            )
        if fault_at == "before_effect":
            raise SimulatedCrash("simulated crash before external effect")
        provider_receipt = self.provider.execute(
            project_id=effect["project_id"],
            idempotency_key=effect["idempotency_key"],
            effect_id=effect_id,
            request_digest=effect["request_digest"],
            request=envelope["request"],
        )
        if fault_at == "after_effect_before_checkpoint":
            raise SimulatedCrash(
                "simulated crash after external effect before checkpoint"
            )
        result = self._checkpoint(effect, provider_receipt)
        if fault_at == "after_checkpoint":
            raise SimulatedCrash("simulated crash after durable checkpoint")
        return result

    def _checkpoint(
        self, effect: Mapping[str, Any], receipt: FakeProviderReceipt
    ) -> DispatchResult:
        effect_id = effect["effect_id"]
        result_digest = content_hash(dict(receipt.result))
        with self.store.transaction(immediate=True) as connection:
            prior = connection.execute(
                "SELECT * FROM effect_receipts WHERE effect_id = ?", (effect_id,)
            ).fetchone()
            if prior is not None:
                receipt_record = _effect_receipt(prior)
                if (
                    receipt_record.result_digest != result_digest
                    or receipt_record.provider_receipt != receipt.provider_receipt
                ):
                    raise IntegrityError("effect receipt reconciliation mismatch")
                return DispatchResult(
                    effect_id=effect_id,
                    status=receipt_record.status,
                    provider_receipt=receipt_record.provider_receipt,
                    result=dict(receipt_record.result),
                    provider_replayed=receipt.replayed,
                    checkpoint_replayed=True,
                )
            version = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
                "WHERE aggregate_type = 'effect' AND aggregate_id = ?",
                (effect_id,),
            ).fetchone()[0]
            self.store.append_event(
                connection,
                aggregate_type="effect",
                aggregate_id=effect_id,
                expected_version=int(version),
                project_id=effect["project_id"],
                run_id=effect["run_id"],
                task_id=effect["task_id"],
                event_type="effect_reconciled",
                actor="fake-provider-adapter",
                command_id=str(uuid.uuid4()),
                correlation_id=effect["run_id"],
                policy_version=self.policy_version,
                payload={
                    "status": receipt.status,
                    "provider_receipt": receipt.provider_receipt,
                    "result_digest": result_digest,
                },
            )
            receipt_id = str(uuid.uuid4())
            now = utc_now()
            connection.execute(
                """
                INSERT INTO effect_receipts(
                    receipt_id, effect_id, status, provider_receipt,
                    result_json, result_digest, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    effect_id,
                    receipt.status,
                    receipt.provider_receipt,
                    canonical_json(dict(receipt.result)),
                    result_digest,
                    now,
                ),
            )
            connection.execute(
                "UPDATE outbox SET status = ?, dispatched_at = ?, reconciled_at = ?, last_error = ? "
                "WHERE effect_id = ?",
                (
                    receipt.status,
                    now,
                    now,
                    receipt.result.get("message")
                    if receipt.status != "succeeded"
                    else None,
                    effect_id,
                ),
            )
            connection.execute(
                "UPDATE workflow_steps SET status = ?, result_json = ?, completed_at = ? "
                "WHERE task_id = ? AND step_id = ?",
                (
                    receipt.status,
                    canonical_json(dict(receipt.result)),
                    now,
                    effect["task_id"],
                    effect["step_id"],
                ),
            )
            if receipt.status != "succeeded":
                self._retain_negative(connection, effect, receipt, now)
        return DispatchResult(
            effect_id=effect_id,
            status=receipt.status,
            provider_receipt=receipt.provider_receipt,
            result=dict(receipt.result),
            provider_replayed=receipt.replayed,
            checkpoint_replayed=False,
        )

    def _checkpoint_authorization_failure(
        self, effect: Mapping[str, Any], error: AuthorizationError
    ) -> DispatchResult:
        """Persist one terminal authorization outcome without calling the provider."""

        effect_id = effect["effect_id"]
        message = str(error).strip() or "effect authorization denied"
        result = {
            "authorization_outcome": "denied",
            "error_class": type(error).__name__,
            "message": message,
            "retryable": False,
            "error_digest": content_hash(
                {"error_class": type(error).__name__, "message": message}
            ),
        }
        result_digest = content_hash(result)
        with self.store.transaction(immediate=True) as connection:
            prior = connection.execute(
                "SELECT * FROM effect_receipts WHERE effect_id = ?", (effect_id,)
            ).fetchone()
            if prior is not None:
                receipt = _effect_receipt(prior)
                return DispatchResult(
                    effect_id=effect_id,
                    status=receipt.status,
                    provider_receipt=receipt.provider_receipt,
                    result=dict(receipt.result),
                    provider_replayed=receipt.provider_receipt is not None,
                    checkpoint_replayed=True,
                )
            version = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
                "WHERE aggregate_type = 'effect' AND aggregate_id = ?",
                (effect_id,),
            ).fetchone()[0]
            self.store.append_event(
                connection,
                aggregate_type="effect",
                aggregate_id=effect_id,
                expected_version=int(version),
                project_id=effect["project_id"],
                run_id=effect["run_id"],
                task_id=effect["task_id"],
                event_type="effect_authorization_failed",
                actor="policy-engine",
                command_id=str(uuid.uuid4()),
                correlation_id=effect["run_id"],
                policy_version=self.policy_version,
                payload={
                    "status": "failed",
                    "result_digest": result_digest,
                    "authorization_outcome": "denied",
                },
            )
            now = utc_now()
            connection.execute(
                """
                INSERT INTO effect_receipts(
                    receipt_id, effect_id, status, provider_receipt,
                    result_json, result_digest, recorded_at
                ) VALUES (?, ?, 'failed', NULL, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    effect_id,
                    canonical_json(result),
                    result_digest,
                    now,
                ),
            )
            connection.execute(
                "UPDATE outbox SET status = 'failed', reconciled_at = ?, last_error = ? "
                "WHERE effect_id = ?",
                (now, message, effect_id),
            )
            connection.execute(
                "UPDATE workflow_steps SET status = 'failed', result_json = ?, completed_at = ? "
                "WHERE task_id = ? AND step_id = ?",
                (
                    canonical_json(result),
                    now,
                    effect["task_id"],
                    effect["step_id"],
                ),
            )
            self._retain_negative(
                connection,
                effect,
                FakeProviderReceipt(
                    provider_receipt=None,
                    status="failed",
                    result=result,
                    replayed=False,
                ),
                now,
            )
        return DispatchResult(
            effect_id=effect_id,
            status="failed",
            provider_receipt=None,
            result=result,
            provider_replayed=False,
            checkpoint_replayed=False,
        )

    @staticmethod
    def _retain_negative(
        connection: Any,
        effect: Mapping[str, Any],
        receipt: FakeProviderReceipt,
        now: str,
    ) -> None:
        fingerprint = content_hash(
            {
                "adapter": effect["adapter"],
                "error_class": receipt.result.get("error_class", "UnknownFailure"),
                "message": receipt.result.get("message", ""),
            }
        )
        prior = connection.execute(
            "SELECT failure_id FROM negative_results WHERE project_id = ? AND task_id = ? AND fingerprint = ?",
            (effect["project_id"], effect["task_id"], fingerprint),
        ).fetchone()
        if prior is None:
            connection.execute(
                """
                INSERT INTO negative_results(
                    failure_id, project_id, run_id, task_id, fingerprint,
                    failure_class, severity, evidence_refs_json, repair_route,
                    first_seen, last_seen, recurrence_count
                ) VALUES (?, ?, ?, ?, ?, ?, 'error', '[]', ?, ?, ?, 1)
                """,
                (
                    str(uuid.uuid4()),
                    effect["project_id"],
                    effect["run_id"],
                    effect["task_id"],
                    fingerprint,
                    receipt.result.get("error_class", "UnknownFailure"),
                    "inspect_effect_authorization_failure"
                    if receipt.result.get("authorization_outcome") == "denied"
                    else "inspect_fake_provider_failure",
                    now,
                    now,
                ),
            )
        else:
            connection.execute(
                "UPDATE negative_results SET last_seen = ?, recurrence_count = recurrence_count + 1 "
                "WHERE failure_id = ?",
                (now, prior["failure_id"]),
            )

    def recover_pending(self, *, limit: int = 100) -> list[DispatchResult]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ContractError("limit must be a positive integer")
        rows = self.store.query(
            "SELECT * FROM outbox WHERE status IN ('authorization_pending', 'ready') "
            "ORDER BY created_at, effect_id LIMIT ?",
            (limit,),
        )
        results: list[DispatchResult] = []
        for row in rows:
            try:
                results.append(self.dispatch(row["effect_id"]))
            except AuthorizationError as error:
                results.append(self._checkpoint_authorization_failure(row, error))
        return results
