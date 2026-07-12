"""Fail-closed, task-bounded capability grants backed by SQLite."""

from __future__ import annotations

import json
import re
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from .errors import AuthorizationError, ContractError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .scope import scope_allowed, scopes_overlap, validate_task_within_goal
from .store import SQLiteStore, protected_authority_config_digest
from .types import Capability, GoalSpec, LoopState, TaskSpec, TaskState, content_hash


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECISION_GATE_CAPABILITIES = {
    "provider": Capability.PROVIDER_COST.value,
    "merge": Capability.REPO_REMOTE.value,
    "release": Capability.PUBLIC_RELEASE.value,
}


def _required_decision_gates_satisfied(connection: Any, task_id: str) -> bool:
    binding = connection.execute(
        "SELECT required_decision_gates_json FROM task_authority_bindings WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    if binding is None:
        return True
    gates = json.loads(binding["required_decision_gates_json"])
    for gate in gates:
        capability = _DECISION_GATE_CAPABILITIES.get(gate)
        clause = "capability = ?" if capability is not None else "action = ?"
        value = capability if capability is not None else gate
        approved = connection.execute(
            f"SELECT 1 FROM approvals WHERE task_id = ? AND {clause} "
            "AND decision = 'approved' AND julianday(expires_at) > julianday('now') LIMIT 1",
            (task_id, value),
        ).fetchone()
        if approved is None:
            return False
    return True

# Every capability has one explicit TaskSpec scope source and a closed action
# vocabulary. Network is the only dual-mode capability: its exact action
# determines whether read_scope or write_scope is authoritative. Adding a new
# Capability without updating both tables fails closed in ``_scope_kind``.
_CAPABILITY_SCOPE_KIND: dict[Capability, str] = {
    Capability.READ_LOCAL: "read",
    Capability.WRITE_LOCAL: "write",
    Capability.EXTERNAL_DOWNLOAD: "read",
    Capability.REPO_REMOTE: "write",
    Capability.SERVER_READ: "read",
    Capability.SERVER_WRITE: "write",
    Capability.PROVIDER_COST: "write",
    Capability.PUBLIC_RELEASE: "write",
    Capability.DESTRUCTIVE: "write",
    Capability.DURABLE_MEMORY_PROMOTION: "write",
    Capability.ACTIVE_RULE_PROMOTION: "write",
    Capability.CONTROL_RESUME: "write",
}
_CAPABILITY_ACTIONS: dict[Capability, frozenset[str]] = {
    Capability.READ_LOCAL: frozenset(
        {"exists", "hash", "inspect", "list", "read", "stat"}
    ),
    Capability.WRITE_LOCAL: frozenset(
        {
            "copy",
            "create",
            "format",
            "mkdir",
            "patch",
            "synthetic_write",
            "update",
            "write",
        }
    ),
    Capability.EXTERNAL_DOWNLOAD: frozenset({"download", "fetch", "get", "head"}),
    Capability.REPO_REMOTE: frozenset({"open_pr", "push", "update_pr"}),
    Capability.SERVER_READ: frozenset(
        {"inspect", "list", "logs", "probe", "query", "read", "status"}
    ),
    Capability.SERVER_WRITE: frozenset(
        {"configure", "deploy", "reload", "restart", "start", "stop", "upload", "write"}
    ),
    Capability.PROVIDER_COST: frozenset(
        {"call", "embed", "generate", "invoke", "synthesize", "transcribe"}
    ),
    Capability.PUBLIC_RELEASE: frozenset({"publish", "release"}),
    Capability.DESTRUCTIVE: frozenset(
        {"delete", "drop", "purge", "remove", "truncate"}
    ),
    Capability.DURABLE_MEMORY_PROMOTION: frozenset({"promote_memory"}),
    Capability.ACTIVE_RULE_PROMOTION: frozenset(
        {"promote_improvement:active", "promote_improvement:limited"}
    ),
    Capability.CONTROL_RESUME: frozenset({"resume", "resume_run", "resume_task"}),
}
_NETWORK_READ_ACTIONS = frozenset(
    {"download", "fetch", "get", "head", "inspect", "list", "probe", "query", "read"}
)
_NETWORK_WRITE_ACTIONS = frozenset(
    {
        "call",
        "connect",
        "invoke",
        "patch",
        "post",
        "publish",
        "put",
        "send",
        "upload",
        "write",
    }
)
_EXECUTABLE_RUN_STATES = frozenset({LoopState.READY, LoopState.RUNNING})
_EXECUTABLE_TASK_STATES = frozenset(
    {TaskState.READY, TaskState.LEASED, TaskState.RUNNING}
)
_INTEGRATION_RUN_STATES = frozenset(
    {
        LoopState.READY,
        LoopState.RUNNING,
        LoopState.EVIDENCE_PENDING,
        LoopState.INTEGRATION_PENDING,
        LoopState.CI_PENDING,
        LoopState.DEPLOY_DIR_UPDATED,
        LoopState.RUNTIME_STALE,
        LoopState.RUNTIME_CHECK_PENDING,
        LoopState.RUNTIME_FRESH,
    }
)
_INTEGRATION_TASK_STATES = frozenset(
    {
        TaskState.READY,
        TaskState.LEASED,
        TaskState.RUNNING,
        TaskState.EVIDENCE_PENDING,
        TaskState.EVALUATOR_PENDING,
        TaskState.INTEGRATION_PENDING,
    }
)
_INTEGRATION_CAPABILITIES = frozenset(
    {
        Capability.REPO_REMOTE,
        Capability.SERVER_READ,
        Capability.SERVER_WRITE,
        Capability.PUBLIC_RELEASE,
        Capability.DESTRUCTIVE,
    }
)
_PROMOTION_CAPABILITIES = frozenset(
    {
        Capability.DURABLE_MEMORY_PROMOTION,
        Capability.ACTIVE_RULE_PROMOTION,
    }
)
_CAPABILITY_EXECUTION_ROLES: dict[Capability, frozenset[Role]] = {
    capability: frozenset({Role.WORKER, Role.SYSTEM}) for capability in Capability
}
_CAPABILITY_EXECUTION_ROLES.update(
    {
        Capability.REPO_REMOTE: frozenset({Role.WORKER, Role.RELEASE, Role.SYSTEM}),
        Capability.SERVER_WRITE: frozenset({Role.WORKER, Role.RELEASE, Role.SYSTEM}),
        Capability.PUBLIC_RELEASE: frozenset({Role.RELEASE, Role.SYSTEM}),
        Capability.DESTRUCTIVE: frozenset({Role.WORKER, Role.OWNER, Role.SYSTEM}),
        Capability.DURABLE_MEMORY_PROMOTION: frozenset({Role.OWNER, Role.SYSTEM}),
        Capability.ACTIVE_RULE_PROMOTION: frozenset({Role.OWNER, Role.SYSTEM}),
        Capability.CONTROL_RESUME: frozenset({Role.OWNER, Role.SYSTEM}),
    }
)


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    project_id: str
    goal_id: str
    run_id: str
    task_id: str
    requester: str
    approver: str
    capability: str
    action: str
    resource: str
    request_digest: str
    policy_version: str
    decision: str
    requested_at: str
    decided_at: str
    expires_at: str


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    project_id: str
    goal_id: str
    run_id: str
    task_id: str
    approval_id: str
    issuer: str
    principal: str
    capability: str
    action: str
    resource: str
    request_digest: str
    policy_version: str
    not_before: str
    expires_at: str
    max_uses: int
    used_count: int
    cost_limit: int
    cost_used: int
    required_fence: int | None
    revoked_at: str | None


@dataclass(frozen=True)
class CapabilityUse:
    grant_id: str
    idempotency_key: str
    request_digest: str
    cost: int
    used_at: str
    effect_id: str | None
    used_count: int
    cost_used: int
    required_fence: int | None
    replayed: bool


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"{field} must be a non-empty string")
    return value.strip()


def _digest(value: str) -> str:
    value = _required_text(value, "request_digest").lower()
    if not _SHA256.fullmatch(value):
        raise AuthorizationError(
            "request_digest must be a lowercase SHA-256 hex digest"
        )
    return value


def _positive_int(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AuthorizationError(f"{field} must be a positive integer")
    return value


def _cost(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorizationError(f"{field} must be a non-negative minor-unit integer")
    return value


def _capability(value: Capability | str) -> str:
    try:
        return Capability(value).value
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(f"unsupported capability: {value}") from exc


def _fence(value: int | None) -> int | None:
    if value is None:
        return None
    return _positive_int(value, "fence")


def _scope_kind(capability: str, action: str) -> str:
    capability_member = Capability(capability)
    normalized_action = action.strip().casefold()
    if action != normalized_action:
        raise AuthorizationError("action must use its canonical lowercase spelling")
    if capability_member is Capability.NETWORK:
        if normalized_action in _NETWORK_READ_ACTIONS:
            return "read"
        if normalized_action in _NETWORK_WRITE_ACTIONS:
            return "write"
        raise AuthorizationError(
            f"network action has no fail-closed scope mapping: {action}"
        )
    try:
        scope_kind = _CAPABILITY_SCOPE_KIND[capability_member]
        allowed_actions = _CAPABILITY_ACTIONS[capability_member]
    except KeyError as exc:  # pragma: no cover - guards future enum additions
        raise AuthorizationError(
            f"capability has no fail-closed scope mapping: {capability}"
        ) from exc
    if normalized_action not in allowed_actions:
        raise AuthorizationError(
            f"action is not allowed for capability {capability}: {action}"
        )
    return scope_kind


def _assert_execution_role(roles: frozenset[Role], capability: str) -> None:
    member = Capability(capability)
    try:
        allowed = _CAPABILITY_EXECUTION_ROLES[member]
    except KeyError as exc:  # pragma: no cover - guards future enum additions
        raise AuthorizationError(
            f"capability has no execution-role mapping: {capability}"
        ) from exc
    if roles.isdisjoint(allowed):
        expected = ", ".join(sorted(role.value for role in allowed))
        raise AuthorizationError(
            f"principal lacks an execution role for {capability}: requires {expected}"
        )


def _approval_record(row: Any) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row["approval_id"],
        project_id=row["project_id"],
        goal_id=row["goal_id"],
        run_id=row["run_id"],
        task_id=row["task_id"],
        requester=row["requester"],
        approver=row["approver"],
        capability=row["capability"],
        action=row["action"],
        resource=row["resource"],
        request_digest=row["request_digest"],
        policy_version=row["policy_version"],
        decision=row["decision"],
        requested_at=row["requested_at"],
        decided_at=row["decided_at"],
        expires_at=row["expires_at"],
    )


def _grant_record(row: Any) -> CapabilityGrant:
    return CapabilityGrant(
        grant_id=row["grant_id"],
        project_id=row["project_id"],
        goal_id=row["goal_id"],
        run_id=row["run_id"],
        task_id=row["task_id"],
        approval_id=row["approval_id"],
        issuer=row["issuer"],
        principal=row["principal"],
        capability=row["capability"],
        action=row["action"],
        resource=row["resource"],
        request_digest=row["request_digest"],
        policy_version=row["policy_version"],
        not_before=row["not_before"],
        expires_at=row["expires_at"],
        max_uses=int(row["max_uses"]),
        used_count=int(row["used_count"]),
        cost_limit=int(row["cost_limit"]),
        cost_used=int(row["cost_used"]),
        required_fence=int(row["required_fence"])
        if row["required_fence"] is not None
        else None,
        revoked_at=row["revoked_at"],
    )


class PolicyEngine:
    """Creates approval-backed grants and consumes them atomically.

    Grants are bound to one task, principal, capability, action, resource and
    request digest. A usage replay without a durable effect receipt must pass
    revocation, expiry and current-fence checks again. Completed receipts are
    reconciled by the workflow before this authorization path is entered.
    """

    def __init__(self, store: SQLiteStore, *, identity: IdentityManager | None = None):
        self.store = store
        self.identity = identity or IdentityManager(store)
        self.__command_authority = store._bind_protected_command_authority(
            self,
            "policy_engine",
            config_digest=protected_authority_config_digest("policy_engine"),
        )

    @staticmethod
    def _now(connection: Any) -> str:
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        ).fetchone()[0]

    @staticmethod
    def _expires(connection: Any, ttl_seconds: int) -> str:
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
            (f"+{ttl_seconds} seconds",),
        ).fetchone()[0]

    @staticmethod
    def _assert_task_scope(
        connection: Any,
        *,
        project_id: str,
        goal_id: str,
        run_id: str,
        task_id: str,
    ) -> Any:
        row = connection.execute(
            """
            SELECT t.spec_json, g.spec_json AS goal_spec_json,
                   t.state AS task_state,
                   r.loop_state AS run_state
            FROM tasks AS t
            JOIN runs AS r ON r.run_id = t.run_id
            JOIN goals AS g ON g.goal_id = t.goal_id
            WHERE t.task_id = ? AND t.project_id = ? AND t.goal_id = ?
              AND t.run_id = ? AND r.project_id = ? AND r.goal_id = ?
              AND g.project_id = ?
            """,
            (
                task_id,
                project_id,
                goal_id,
                run_id,
                project_id,
                goal_id,
                project_id,
            ),
        ).fetchone()
        if row is None:
            raise AuthorizationError(
                f"task scope does not exist: {project_id}/{goal_id}/{run_id}/{task_id}"
            )
        return row

    @staticmethod
    def _assert_task_lifecycle(task_row: Any, *, capability: str, phase: str) -> None:
        try:
            task_state = TaskState(task_row["task_state"])
            run_state = LoopState(task_row["run_state"])
            capability_member = Capability(capability)
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationError(
                "task/run lifecycle projection is invalid"
            ) from exc
        if capability_member in _PROMOTION_CAPABILITIES:
            if phase != "approval":
                raise AuthorizationError(
                    "memory/rule promotion is an approval-backed governance "
                    "decision, not an executable capability grant"
                )
            if task_state in {
                TaskState.CANCELED,
                TaskState.DELETED,
                TaskState.RETIRED,
            }:
                raise AuthorizationError(
                    "canceled/deleted/retired task cannot authorize promotion"
                )
            # The source run may already be delivered. Promotion registries
            # separately verify candidate, evaluation, limited-state and exact
            # approval invariants.
            return
        if capability_member is Capability.CONTROL_RESUME:
            if run_state not in {
                LoopState.SUSPENDED,
                LoopState.BLOCKED_CAPABILITY,
                LoopState.BLOCKED_DECISION,
                LoopState.BLOCKED_MISSING_STATE,
            }:
                raise AuthorizationError(
                    "control_resume requires a suspended/blocked run"
                )
            if task_state in {
                TaskState.DELIVERED,
                TaskState.CANCELED,
                TaskState.DELETED,
                TaskState.RETIRED,
            }:
                raise AuthorizationError(
                    "terminal task is sealed against authorization"
                )
            return
        allowed_run_states = (
            _INTEGRATION_RUN_STATES
            if capability_member in _INTEGRATION_CAPABILITIES
            else _EXECUTABLE_RUN_STATES
        )
        allowed_task_states = (
            _INTEGRATION_TASK_STATES
            if capability_member in _INTEGRATION_CAPABILITIES
            else _EXECUTABLE_TASK_STATES
        )
        if phase == "consume":
            if capability_member in _INTEGRATION_CAPABILITIES:
                allowed_run_states = allowed_run_states - {LoopState.READY}
                allowed_task_states = allowed_task_states - {
                    TaskState.READY,
                    TaskState.LEASED,
                }
            else:
                allowed_run_states = frozenset({LoopState.RUNNING})
                allowed_task_states = frozenset({TaskState.RUNNING})
        if run_state not in allowed_run_states:
            raise AuthorizationError(
                f"run is sealed or not executable for authorization: {run_state.value}"
            )
        if task_state not in allowed_task_states:
            raise AuthorizationError(
                f"task is sealed or not executable for authorization: {task_state.value}"
            )

    @staticmethod
    def _assert_task_authority(
        task_row: Any, *, capability: str, action: str, resource: str
    ) -> None:
        try:
            spec = TaskSpec.from_dict(json.loads(task_row["spec_json"]))
            goal = GoalSpec.from_dict(json.loads(task_row["goal_spec_json"]))
            validate_task_within_goal(goal, spec)
            capability_member = Capability(capability)
            if capability_member not in spec.capabilities:
                raise AuthorizationError(
                    f"task contract does not allow capability: {capability}"
                )
            scope_kind = _scope_kind(capability, action)
            if any(
                scopes_overlap(resource, forbidden)
                for forbidden in spec.forbidden_scope
            ):
                raise AuthorizationError(f"task contract forbids resource: {resource}")
            allowed_scopes = (
                spec.read_scope if scope_kind == "read" else spec.write_scope
            )
            if not scope_allowed(allowed_scopes, resource):
                raise AuthorizationError(
                    "task contract does not authorize "
                    f"{scope_kind}_scope resource for {capability}/{action}: {resource}"
                )
        except AuthorizationError:
            raise
        except (ContractError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuthorizationError(
                "task has no valid compiled authority contract"
            ) from exc

    @staticmethod
    def _assert_current_lease(
        connection: Any,
        *,
        resource: str,
        project_id: str,
        task_id: str,
        principal: str,
        fence: int,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM leases
            WHERE resource_key = ? AND project_id = ? AND task_id = ?
              AND holder = ? AND fence = ? AND released_at IS NULL
              AND julianday(expires_at) > julianday('now')
            """,
            (resource, project_id, task_id, principal, fence),
        ).fetchone()
        if row is None:
            raise AuthorizationError(
                f"required lease fence is not current: {resource} at fence {fence}"
            )

    @staticmethod
    def _assert_current_task_claim(
        connection: Any,
        *,
        project_id: str,
        task_id: str,
        principal: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM leases
            WHERE resource_key = ? AND project_id = ? AND task_id = ?
              AND holder = ? AND released_at IS NULL
              AND julianday(expires_at) > julianday('now')
            """,
            (f"task://{task_id}", project_id, task_id, principal),
        ).fetchone()
        if row is None:
            raise AuthorizationError(
                f"worker has no current task claim: task://{task_id}"
            )

    def record_approval(
        self,
        *,
        project_id: str,
        goal_id: str,
        run_id: str,
        task_id: str,
        requester: VerifiedPrincipal,
        approver: VerifiedPrincipal,
        capability: Capability | str,
        action: str,
        resource: str,
        request_digest: str,
        policy_version: str,
        decision: str,
        ttl_seconds: int,
        approval_id: str | None = None,
    ) -> ApprovalRecord:
        project_id = _required_text(project_id, "project_id")
        goal_id = _required_text(goal_id, "goal_id")
        run_id = _required_text(run_id, "run_id")
        task_id = _required_text(task_id, "task_id")
        capability_value = _capability(capability)
        action = _required_text(action, "action")
        resource = _required_text(resource, "resource")
        request_digest = _digest(request_digest)
        policy_version = _required_text(policy_version, "policy_version")
        if decision not in {"approved", "denied"}:
            raise AuthorizationError("decision must be approved or denied")
        ttl_seconds = _positive_int(ttl_seconds, "ttl_seconds")
        approval_id = _required_text(approval_id or str(uuid.uuid4()), "approval_id")

        with self.store.transaction(immediate=True) as connection:
            requester_record = self.identity.verify_in_transaction(
                connection, requester
            )
            approver_record = self.identity.require_role_in_transaction(
                connection, approver, Role.OWNER
            )
            requester_id = requester_record.principal_id
            approver_id = approver_record.principal_id
            if requester_id == approver_id:
                raise AuthorizationError(
                    "requester and approver must be different principals"
                )
            task_scope = self._assert_task_scope(
                connection,
                project_id=project_id,
                goal_id=goal_id,
                run_id=run_id,
                task_id=task_id,
            )
            self._assert_task_authority(
                task_scope,
                capability=capability_value,
                action=action,
                resource=resource,
            )
            self._assert_task_lifecycle(
                task_scope, capability=capability_value, phase="approval"
            )
            now = self._now(connection)
            expires_at = self._expires(connection, ttl_seconds)
            self.store.append_event(
                connection,
                aggregate_type="approval",
                aggregate_id=approval_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                task_id=task_id,
                event_type="approval_decided",
                actor=approver_id,
                command_id=str(uuid.uuid4()),
                correlation_id=run_id,
                policy_version=policy_version,
                payload={
                    "requester": requester_id,
                    "capability": capability_value,
                    "action": action,
                    "resource": resource,
                    "request_digest": request_digest,
                    "decision": decision,
                    "expires_at": expires_at,
                },
                command_authority=self.__command_authority,
                command_owner=self,
            )
            connection.execute(
                """
                INSERT INTO approvals(
                    approval_id, project_id, goal_id, run_id, task_id,
                    requester, approver, capability, action, resource,
                    request_digest, policy_version, decision, requested_at,
                    decided_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    project_id,
                    goal_id,
                    run_id,
                    task_id,
                    requester_id,
                    approver_id,
                    capability_value,
                    action,
                    resource,
                    request_digest,
                    policy_version,
                    decision,
                    now,
                    now,
                    expires_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            return _approval_record(row)

    def issue_grant(
        self,
        *,
        approval_id: str,
        issuer: VerifiedPrincipal,
        principal: VerifiedPrincipal,
        capability: Capability | str,
        action: str,
        resource: str,
        request_digest: str,
        policy_version: str,
        ttl_seconds: int,
        max_uses: int = 1,
        cost_limit: int = 0,
        required_fence: int | None = None,
        grant_id: str | None = None,
    ) -> CapabilityGrant:
        approval_id = _required_text(approval_id, "approval_id")
        capability_value = _capability(capability)
        action = _required_text(action, "action")
        resource = _required_text(resource, "resource")
        request_digest = _digest(request_digest)
        policy_version = _required_text(policy_version, "policy_version")
        ttl_seconds = _positive_int(ttl_seconds, "ttl_seconds")
        max_uses = _positive_int(max_uses, "max_uses")
        cost_limit = _cost(cost_limit, "cost_limit")
        required_fence = _fence(required_fence)
        grant_id = _required_text(grant_id or str(uuid.uuid4()), "grant_id")

        with self.store.transaction(immediate=True) as connection:
            issuer_record = self.identity.require_role_in_transaction(
                connection, issuer, Role.OWNER
            )
            principal_record = self.identity.verify_in_transaction(
                connection, principal
            )
            issuer_id = issuer_record.principal_id
            principal_id = principal_record.principal_id
            _assert_execution_role(principal_record.roles, capability_value)
            approval = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if approval is None:
                raise AuthorizationError(f"approval does not exist: {approval_id}")
            if approval["decision"] != "approved":
                raise AuthorizationError(f"approval is not approved: {approval_id}")
            if (
                approval["approver"] != issuer_id
                or approval["requester"] != principal_id
            ):
                raise AuthorizationError(
                    "issuer/principal do not match the approval actors"
                )
            expected = (
                approval["capability"],
                approval["action"],
                approval["resource"],
                approval["request_digest"],
                approval["policy_version"],
            )
            requested = (
                capability_value,
                action,
                resource,
                request_digest,
                policy_version,
            )
            if expected != requested:
                raise AuthorizationError(
                    "grant request does not exactly match the approval"
                )
            active = connection.execute(
                "SELECT julianday(?) > julianday('now')", (approval["expires_at"],)
            ).fetchone()[0]
            if active != 1:
                raise AuthorizationError(f"approval has expired: {approval_id}")
            if not _required_decision_gates_satisfied(
                connection, approval["task_id"]
            ):
                raise AuthorizationError(
                    "compiled Task required decision gates are not satisfied"
                )

            task_scope = self._assert_task_scope(
                connection,
                project_id=approval["project_id"],
                goal_id=approval["goal_id"],
                run_id=approval["run_id"],
                task_id=approval["task_id"],
            )
            self._assert_task_authority(
                task_scope,
                capability=capability_value,
                action=action,
                resource=resource,
            )
            self._assert_task_lifecycle(
                task_scope, capability=capability_value, phase="grant"
            )
            if capability_value != Capability.PROVIDER_COST.value and cost_limit != 0:
                raise AuthorizationError(
                    "cost_limit is a minor-unit provider budget and must be zero for other capabilities"
                )
            if capability_value == Capability.PROVIDER_COST.value:
                goal_row = connection.execute(
                    "SELECT spec_json FROM goals WHERE goal_id = ?",
                    (approval["goal_id"],),
                ).fetchone()
                from .types import GoalSpec

                goal = GoalSpec.from_dict(json.loads(goal_row["spec_json"]))
                reserved = connection.execute(
                    "SELECT COALESCE(SUM(cost_limit), 0) AS cost, "
                    "COALESCE(SUM(max_uses), 0) AS calls FROM capability_grants "
                    "WHERE run_id = ? AND capability = ? AND revoked_at IS NULL "
                    "AND julianday(expires_at) > julianday('now')",
                    (approval["run_id"], Capability.PROVIDER_COST.value),
                ).fetchone()
                if (
                    int(reserved["cost"]) + cost_limit
                    > goal.provider_budget_minor_units
                ):
                    raise AuthorizationError(
                        "goal provider budget reservation would be exceeded"
                    )
                if int(reserved["calls"]) + max_uses > goal.provider_call_limit:
                    raise AuthorizationError(
                        "goal provider call limit reservation would be exceeded"
                    )
                task_authority = connection.execute(
                    "SELECT provider_budget_minor_units, provider_call_limit "
                    "FROM task_authority_bindings WHERE task_id = ?",
                    (approval["task_id"],),
                ).fetchone()
                if task_authority is not None:
                    task_reserved = connection.execute(
                        "SELECT COALESCE(SUM(cost_limit), 0) AS cost, "
                        "COALESCE(SUM(max_uses), 0) AS calls FROM capability_grants "
                        "WHERE task_id = ? AND capability = ? AND revoked_at IS NULL "
                        "AND julianday(expires_at) > julianday('now')",
                        (approval["task_id"], Capability.PROVIDER_COST.value),
                    ).fetchone()
                    if int(task_reserved["cost"]) + cost_limit > int(
                        task_authority["provider_budget_minor_units"]
                    ):
                        raise AuthorizationError(
                            "compiled Task provider budget reservation would be exceeded"
                        )
                    if int(task_reserved["calls"]) + max_uses > int(
                        task_authority["provider_call_limit"]
                    ):
                        raise AuthorizationError(
                            "compiled Task provider call limit reservation would be exceeded"
                        )
            if required_fence is not None:
                self._assert_current_lease(
                    connection,
                    resource=resource,
                    project_id=approval["project_id"],
                    task_id=approval["task_id"],
                    principal=principal_id,
                    fence=required_fence,
                )

            not_before = self._now(connection)
            expires_at = self._expires(connection, ttl_seconds)
            within_approval = connection.execute(
                "SELECT julianday(?) <= julianday(?)",
                (expires_at, approval["expires_at"]),
            ).fetchone()[0]
            if within_approval != 1:
                raise AuthorizationError("grant cannot outlive its approval")
            self.store.append_event(
                connection,
                aggregate_type="grant",
                aggregate_id=grant_id,
                expected_version=0,
                project_id=approval["project_id"],
                run_id=approval["run_id"],
                task_id=approval["task_id"],
                event_type="capability_grant_issued",
                actor=issuer_id,
                command_id=str(uuid.uuid4()),
                correlation_id=approval["run_id"],
                policy_version=policy_version,
                payload={
                    "approval_id": approval_id,
                    "principal": principal_id,
                    "capability": capability_value,
                    "action": action,
                    "resource": resource,
                    "request_digest": request_digest,
                    "not_before": not_before,
                    "expires_at": expires_at,
                    "max_uses": max_uses,
                    "cost_limit": cost_limit,
                    "required_fence": required_fence,
                },
            )
            connection.execute(
                """
                INSERT INTO capability_grants(
                    grant_id, project_id, goal_id, run_id, task_id,
                    approval_id, issuer, principal, capability, action,
                    resource, request_digest, policy_version, not_before,
                    expires_at, max_uses, used_count, cost_limit, cost_used,
                    required_fence, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, NULL)
                """,
                (
                    grant_id,
                    approval["project_id"],
                    approval["goal_id"],
                    approval["run_id"],
                    approval["task_id"],
                    approval_id,
                    issuer_id,
                    principal_id,
                    capability_value,
                    action,
                    resource,
                    request_digest,
                    policy_version,
                    not_before,
                    expires_at,
                    max_uses,
                    cost_limit,
                    required_fence,
                ),
            )
            row = connection.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            return _grant_record(row)

    def revoke_grant(
        self, grant_id: str, *, actor: VerifiedPrincipal
    ) -> CapabilityGrant:
        grant_id = _required_text(grant_id, "grant_id")
        with self.store.transaction(immediate=True) as connection:
            actor_id = self.identity.require_role_in_transaction(
                connection, actor, Role.OWNER
            ).principal_id
            row = connection.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if row is None:
                raise AuthorizationError(f"grant does not exist: {grant_id}")
            if row["revoked_at"] is None:
                version = connection.execute(
                    "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
                    "WHERE aggregate_type = 'grant' AND aggregate_id = ?",
                    (grant_id,),
                ).fetchone()[0]
                self.store.append_event(
                    connection,
                    aggregate_type="grant",
                    aggregate_id=grant_id,
                    expected_version=int(version),
                    project_id=row["project_id"],
                    run_id=row["run_id"],
                    task_id=row["task_id"],
                    event_type="capability_grant_revoked",
                    actor=actor_id,
                    command_id=str(uuid.uuid4()),
                    correlation_id=row["run_id"],
                    policy_version=row["policy_version"],
                    payload={"grant_id": grant_id},
                )
                connection.execute(
                    "UPDATE capability_grants SET revoked_at = ? WHERE grant_id = ?",
                    (self._now(connection), grant_id),
                )
                row = connection.execute(
                    "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
                ).fetchone()
            return _grant_record(row)

    def consume(
        self,
        grant_id: str,
        *,
        project_id: str,
        goal_id: str,
        run_id: str,
        task_id: str,
        principal: VerifiedPrincipal,
        capability: Capability | str,
        action: str,
        resource: str,
        request_digest: str,
        idempotency_key: str,
        cost: int = 0,
        fence: int | None = None,
        effect_id: str | None = None,
    ) -> CapabilityUse:
        return self._consume_as_principal(
            grant_id,
            project_id=project_id,
            goal_id=goal_id,
            run_id=run_id,
            task_id=task_id,
            principal=None,
            auth_session=principal,
            capability=capability,
            action=action,
            resource=resource,
            request_digest=request_digest,
            idempotency_key=idempotency_key,
            cost=cost,
            fence=fence,
            effect_id=effect_id,
        )

    def preflight_effect_authority(
        self,
        connection: Any,
        *,
        grant_id: str,
        project_id: str,
        goal_id: str,
        run_id: str,
        task_id: str,
        principal: VerifiedPrincipal,
        capability: Capability | str,
        action: str,
        resource: str,
        request_digest: str,
        policy_version: str,
        fence: int | None,
    ) -> None:
        """Validate an enqueue envelope without reserving or consuming use.

        Dispatch repeats all checks and performs the atomic consumption. This
        preflight prevents an unauthorized caller or malformed grant from
        permanently occupying a declared workflow step before dispatch.
        """

        if not connection.in_transaction:
            raise AuthorizationError("effect preflight requires an active transaction")
        grant_id = _required_text(grant_id, "grant_id")
        capability_value = _capability(capability)
        action = _required_text(action, "action")
        resource = _required_text(resource, "resource")
        request_digest = _digest(request_digest)
        policy_version = _required_text(policy_version, "policy_version")
        fence = _fence(fence)
        principal_record = self.identity.verify_in_transaction(connection, principal)
        _assert_execution_role(principal_record.roles, capability_value)
        task_scope = self._assert_task_scope(
            connection,
            project_id=project_id,
            goal_id=goal_id,
            run_id=run_id,
            task_id=task_id,
        )
        self._assert_task_authority(
            task_scope,
            capability=capability_value,
            action=action,
            resource=resource,
        )
        self._assert_task_lifecycle(
            task_scope, capability=capability_value, phase="consume"
        )
        if Role.WORKER in principal_record.roles:
            self._assert_current_task_claim(
                connection,
                project_id=project_id,
                task_id=task_id,
                principal=principal_record.principal_id,
            )
        grant = connection.execute(
            "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if grant is None:
            raise AuthorizationError(f"grant does not exist: {grant_id}")
        expected = (
            project_id,
            goal_id,
            run_id,
            task_id,
            principal_record.principal_id,
            capability_value,
            action,
            resource,
            request_digest,
            policy_version,
        )
        actual = (
            grant["project_id"],
            grant["goal_id"],
            grant["run_id"],
            grant["task_id"],
            grant["principal"],
            grant["capability"],
            grant["action"],
            grant["resource"],
            grant["request_digest"],
            grant["policy_version"],
        )
        if actual != expected:
            raise AuthorizationError("effect envelope does not exactly match the grant")
        if grant["revoked_at"] is not None:
            raise AuthorizationError(f"grant is revoked: {grant_id}")
        valid_time = connection.execute(
            "SELECT julianday(?) <= julianday('now') "
            "AND julianday(?) > julianday('now')",
            (grant["not_before"], grant["expires_at"]),
        ).fetchone()[0]
        if valid_time != 1:
            raise AuthorizationError(f"grant is not currently valid: {grant_id}")
        if int(grant["used_count"]) >= int(grant["max_uses"]):
            raise AuthorizationError(f"grant use limit exhausted: {grant_id}")
        required_fence = (
            int(grant["required_fence"])
            if grant["required_fence"] is not None
            else None
        )
        if required_fence != fence:
            raise AuthorizationError(
                f"fence mismatch: grant requires {required_fence}, request supplied {fence}"
            )
        if required_fence is not None:
            self._assert_current_lease(
                connection,
                resource=resource,
                project_id=project_id,
                task_id=task_id,
                principal=principal_record.principal_id,
                fence=required_fence,
            )

    def _consume_effect(self, effect_id: str) -> CapabilityUse:
        """Consume authority for one immutable persisted outbox envelope."""

        effect_id = _required_text(effect_id, "effect_id")
        with self.store.transaction(immediate=True) as connection:
            effect = connection.execute(
                "SELECT o.*, t.goal_id FROM outbox AS o JOIN tasks AS t "
                "ON t.task_id = o.task_id WHERE o.effect_id = ?",
                (effect_id,),
            ).fetchone()
            if effect is None:
                raise AuthorizationError(f"outbox effect does not exist: {effect_id}")
            try:
                envelope = json.loads(effect["request_json"])
                if not isinstance(envelope, dict):
                    raise TypeError("authority envelope must be an object")
                authority = {
                    "grant_id": envelope["grant_id"],
                    "principal": envelope["principal"],
                    "capability": envelope["capability"],
                    "action": envelope["action"],
                    "resource": envelope["resource"],
                    "fence": envelope["fence"],
                }
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AuthorizationError(
                    "outbox effect has no valid authority envelope"
                ) from exc
            return self._consume_as_principal(
                authority["grant_id"],
                project_id=effect["project_id"],
                goal_id=effect["goal_id"],
                run_id=effect["run_id"],
                task_id=effect["task_id"],
                principal=authority["principal"],
                capability=authority["capability"],
                action=authority["action"],
                resource=authority["resource"],
                request_digest=effect["request_digest"],
                idempotency_key=f"effect:{effect_id}",
                cost=0,
                fence=authority["fence"],
                effect_id=effect_id,
                connection=connection,
            )

    def _consume_as_principal(
        self,
        grant_id: str,
        *,
        project_id: str,
        goal_id: str,
        run_id: str,
        task_id: str,
        principal: str | None,
        capability: Capability | str,
        action: str,
        resource: str,
        request_digest: str,
        idempotency_key: str,
        cost: int = 0,
        fence: int | None = None,
        effect_id: str | None = None,
        auth_session: VerifiedPrincipal | None = None,
        connection: Any | None = None,
    ) -> CapabilityUse:
        grant_id = _required_text(grant_id, "grant_id")
        project_id = _required_text(project_id, "project_id")
        goal_id = _required_text(goal_id, "goal_id")
        run_id = _required_text(run_id, "run_id")
        task_id = _required_text(task_id, "task_id")
        if auth_session is None:
            if principal is None:
                raise AuthorizationError("principal must be a non-empty string")
            principal_value = _required_text(principal, "principal")
        else:
            principal_value = None
        capability_value = _capability(capability)
        action = _required_text(action, "action")
        resource = _required_text(resource, "resource")
        request_digest = _digest(request_digest)
        idempotency_key = _required_text(idempotency_key, "idempotency_key")
        cost = _cost(cost, "cost")
        fence = _fence(fence)
        if effect_id is not None:
            effect_id = _required_text(effect_id, "effect_id")

        transaction = (
            nullcontext(connection)
            if connection is not None
            else self.store.transaction(immediate=True)
        )
        with transaction as connection:
            if auth_session is not None:
                principal_record = self.identity.verify_in_transaction(
                    connection, auth_session
                )
                principal_value = principal_record.principal_id
                live_roles = principal_record.roles
                _assert_execution_role(live_roles, capability_value)
            else:
                current_roles = connection.execute(
                    """
                    SELECT r.role
                    FROM principals AS p
                    JOIN principal_roles AS r ON r.principal_id = p.principal_id
                    WHERE p.principal_id = ? AND p.enabled = 1
                    """,
                    (principal_value,),
                ).fetchall()
                if not current_roles:
                    raise AuthorizationError(
                        "persisted effect principal is disabled or unauthorized"
                    )
                try:
                    live_roles = frozenset(Role(row["role"]) for row in current_roles)
                except ValueError as exc:
                    raise AuthorizationError(
                        "persisted effect principal has an invalid role"
                    ) from exc
                _assert_execution_role(live_roles, capability_value)
            if principal_value is None:  # pragma: no cover - defensive type boundary
                raise AuthorizationError("authenticated principal is missing")
            grant = connection.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if grant is None:
                raise AuthorizationError(f"grant does not exist: {grant_id}")
            exact_scope = (
                grant["project_id"],
                grant["goal_id"],
                grant["run_id"],
                grant["task_id"],
                grant["principal"],
                grant["capability"],
                grant["action"],
                grant["resource"],
                grant["request_digest"],
            )
            request_scope = (
                project_id,
                goal_id,
                run_id,
                task_id,
                principal_value,
                capability_value,
                action,
                resource,
                request_digest,
            )
            if exact_scope != request_scope:
                raise AuthorizationError(
                    "capability request does not exactly match the grant"
                )
            task_scope = self._assert_task_scope(
                connection,
                project_id=project_id,
                goal_id=goal_id,
                run_id=run_id,
                task_id=task_id,
            )
            self._assert_task_authority(
                task_scope,
                capability=capability_value,
                action=action,
                resource=resource,
            )
            self._assert_task_lifecycle(
                task_scope, capability=capability_value, phase="consume"
            )
            if not _required_decision_gates_satisfied(connection, task_id):
                raise AuthorizationError(
                    "compiled Task required decision gates are not satisfied"
                )
            if Role.WORKER in live_roles:
                self._assert_current_task_claim(
                    connection,
                    project_id=project_id,
                    task_id=task_id,
                    principal=principal_value,
                )
            required_fence = (
                int(grant["required_fence"])
                if grant["required_fence"] is not None
                else None
            )
            if required_fence != fence:
                raise AuthorizationError(
                    f"fence mismatch: grant requires {required_fence}, request supplied {fence}"
                )

            usage = connection.execute(
                "SELECT * FROM capability_usage WHERE grant_id = ? AND idempotency_key = ?",
                (grant_id, idempotency_key),
            ).fetchone()
            usage_replay = usage is not None
            if usage is not None:
                if (
                    usage["request_digest"] != request_digest
                    or int(usage["cost"]) != cost
                    or usage["effect_id"] != effect_id
                ):
                    raise AuthorizationError(
                        "idempotency key was already used for a different request"
                    )
            if grant["revoked_at"] is not None:
                raise AuthorizationError(f"grant is revoked: {grant_id}")
            valid_time = connection.execute(
                """
                SELECT julianday(?) <= julianday('now')
                   AND julianday(?) > julianday('now')
                """,
                (grant["not_before"], grant["expires_at"]),
            ).fetchone()[0]
            if valid_time != 1:
                raise AuthorizationError(f"grant is not currently valid: {grant_id}")
            if required_fence is not None:
                self._assert_current_lease(
                    connection,
                    resource=resource,
                    project_id=project_id,
                    task_id=task_id,
                    principal=principal_value,
                    fence=required_fence,
                )

            if usage_replay:
                return CapabilityUse(
                    grant_id=grant_id,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    cost=cost,
                    used_at=usage["used_at"],
                    effect_id=usage["effect_id"],
                    used_count=int(grant["used_count"]),
                    cost_used=int(grant["cost_used"]),
                    required_fence=required_fence,
                    replayed=True,
                )

            if int(grant["used_count"]) >= int(grant["max_uses"]):
                raise AuthorizationError(f"grant use limit exhausted: {grant_id}")
            if int(grant["cost_used"]) + cost > int(grant["cost_limit"]):
                raise AuthorizationError(f"grant cost limit exceeded: {grant_id}")
            if capability_value == Capability.PROVIDER_COST.value:
                task_authority = connection.execute(
                    "SELECT provider_budget_minor_units, provider_call_limit "
                    "FROM task_authority_bindings WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
                if task_authority is not None:
                    consumed = connection.execute(
                        "SELECT COALESCE(SUM(u.cost), 0) AS cost, COUNT(*) AS calls "
                        "FROM capability_usage AS u JOIN capability_grants AS g "
                        "ON g.grant_id = u.grant_id WHERE g.task_id = ? "
                        "AND g.capability = ?",
                        (task_id, Capability.PROVIDER_COST.value),
                    ).fetchone()
                    if int(consumed["cost"]) + cost > int(
                        task_authority["provider_budget_minor_units"]
                    ):
                        raise AuthorizationError("compiled Task provider budget exceeded")
                    if int(consumed["calls"]) + 1 > int(
                        task_authority["provider_call_limit"]
                    ):
                        raise AuthorizationError("compiled Task provider call limit exceeded")

            used_at = self._now(connection)
            connection.execute(
                """
                INSERT INTO capability_usage(
                    grant_id, idempotency_key, request_digest, cost, used_at, effect_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (grant_id, idempotency_key, request_digest, cost, used_at, effect_id),
            )
            changed = connection.execute(
                """
                UPDATE capability_grants
                SET used_count = used_count + 1, cost_used = cost_used + ?
                WHERE grant_id = ? AND revoked_at IS NULL
                  AND julianday(not_before) <= julianday('now')
                  AND julianday(expires_at) > julianday('now')
                  AND used_count < max_uses
                  AND cost_used + ? <= cost_limit
                """,
                (cost, grant_id, cost),
            ).rowcount
            if changed != 1:
                raise AuthorizationError("grant became invalid during consumption")
            use_id = content_hash(
                {"grant_id": grant_id, "idempotency_key": idempotency_key}
            )
            self.store.append_event(
                connection,
                aggregate_type="capability_use",
                aggregate_id=use_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                task_id=task_id,
                event_type="capability_consumed",
                actor=principal_value,
                command_id=str(uuid.uuid4()),
                correlation_id=run_id,
                policy_version=grant["policy_version"],
                payload={
                    "grant_id": grant_id,
                    "capability": capability_value,
                    "action": action,
                    "resource": resource,
                    "request_digest": request_digest,
                    "cost": cost,
                    "effect_id": effect_id,
                },
                idempotency_key=idempotency_key,
            )
            updated = connection.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            return CapabilityUse(
                grant_id=grant_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                cost=cost,
                used_at=used_at,
                effect_id=effect_id,
                used_count=int(updated["used_count"]),
                cost_used=int(updated["cost_used"]),
                required_fence=required_fence,
                replayed=False,
            )
