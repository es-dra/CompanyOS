"""SQLite-backed single-host leases with monotonic fencing tokens."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from .errors import LeaseError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .store import SQLiteStore


@dataclass(frozen=True)
class LeaseRecord:
    """Canonical public Lease wire DTO.

    Operation-local replay metadata lives on :class:`LeaseOperationResult` and
    is deliberately omitted from ``to_wire``.
    """

    resource_key: str
    project_id: str
    task_id: str
    holder: str
    fence: int
    issued_at: str
    expires_at: str
    released_at: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "resource_key": self.resource_key,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "holder": self.holder,
            "fence": self.fence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "released_at": self.released_at,
        }


@dataclass(frozen=True)
class LeaseOperationResult(LeaseRecord):
    """Lease operation result with non-wire idempotency metadata."""

    replayed: bool = False


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LeaseError(f"{field} must be a non-empty string")
    return value.strip()


def _positive_int(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise LeaseError(f"{field} must be a positive integer")
    return value


def _record(row: Any, *, replayed: bool = False) -> LeaseOperationResult:
    return LeaseOperationResult(
        resource_key=row["resource_key"],
        project_id=row["project_id"],
        task_id=row["task_id"],
        holder=row["holder"],
        fence=int(row["fence"]),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        released_at=row["released_at"],
        replayed=replayed,
    )


class LeaseManager:
    """Coordinates leases in one SQLite database.

    Every mutation uses ``BEGIN IMMEDIATE``. Lease validity and expiry are
    evaluated by SQLite's clock so competing processes use one authoritative
    time source. A resource row is never deleted; each takeover increments its
    fencing token.
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
    ):
        self.store = store
        self.policy_version = policy_version
        self.identity = identity or IdentityManager(store)

    def _holder_id(self, connection: Any, holder: VerifiedPrincipal) -> str:
        principal = self.identity.verify_in_transaction(connection, holder)
        if not principal.roles.intersection({Role.WORKER, Role.SYSTEM}):
            raise LeaseError("lease holder requires worker or system role")
        return principal.principal_id

    @staticmethod
    def _now(connection: Any) -> str:
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        ).fetchone()[0]

    @staticmethod
    def _expires(connection: Any, ttl_seconds: int) -> str:
        modifier = f"+{ttl_seconds} seconds"
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)", (modifier,)
        ).fetchone()[0]

    @staticmethod
    def _is_active(connection: Any, row: Any) -> bool:
        if row["released_at"] is not None:
            return False
        result = connection.execute(
            "SELECT julianday(?) > julianday('now')", (row["expires_at"],)
        ).fetchone()[0]
        return result == 1

    @staticmethod
    def _assert_task_scope(connection: Any, project_id: str, task_id: str) -> Any:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id = ? AND project_id = ?",
            (task_id, project_id),
        ).fetchone()
        if row is None:
            raise LeaseError(f"task is not in project scope: {project_id}/{task_id}")
        return row

    def _append_audit(
        self,
        connection: Any,
        *,
        resource_key: str,
        task: Any,
        holder: str,
        fence: int,
        event_type: str,
        expires_at: str,
    ) -> None:
        version = connection.execute(
            "SELECT COALESCE(MAX(aggregate_version), 0) FROM events "
            "WHERE aggregate_type = 'lease' AND aggregate_id = ?",
            (resource_key,),
        ).fetchone()[0]
        self.store.append_event(
            connection,
            aggregate_type="lease",
            aggregate_id=resource_key,
            expected_version=int(version),
            project_id=task["project_id"],
            run_id=task["run_id"],
            task_id=task["task_id"],
            event_type=event_type,
            actor=holder,
            command_id=str(uuid.uuid4()),
            correlation_id=task["run_id"] or task["goal_id"],
            policy_version=self.policy_version,
            payload={"holder": holder, "fence": fence, "expires_at": expires_at},
        )

    def acquire(
        self,
        *,
        resource_key: str,
        project_id: str,
        task_id: str,
        holder: VerifiedPrincipal,
        ttl_seconds: int,
    ) -> LeaseOperationResult:
        resource_key = _required_text(resource_key, "resource_key")
        project_id = _required_text(project_id, "project_id")
        task_id = _required_text(task_id, "task_id")
        ttl_seconds = _positive_int(ttl_seconds, "ttl_seconds")

        with self.store.transaction(immediate=True) as connection:
            holder_id = self._holder_id(connection, holder)
            task = self._assert_task_scope(connection, project_id, task_id)
            row = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            if row is not None and self._is_active(connection, row):
                if (
                    row["project_id"] == project_id
                    and row["task_id"] == task_id
                    and row["holder"] == holder_id
                ):
                    return _record(row, replayed=True)
                raise LeaseError(
                    f"resource is already leased: {resource_key} "
                    f"by {row['holder']} at fence {row['fence']}"
                )

            issued_at = self._now(connection)
            expires_at = self._expires(connection, ttl_seconds)
            if row is None:
                connection.execute(
                    """
                    INSERT INTO leases(
                        resource_key, project_id, task_id, holder, fence,
                        issued_at, expires_at, released_at
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, NULL)
                    """,
                    (
                        resource_key,
                        project_id,
                        task_id,
                        holder_id,
                        issued_at,
                        expires_at,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE leases
                    SET project_id = ?, task_id = ?, holder = ?, fence = fence + 1,
                        issued_at = ?, expires_at = ?, released_at = NULL
                    WHERE resource_key = ?
                    """,
                    (
                        project_id,
                        task_id,
                        holder_id,
                        issued_at,
                        expires_at,
                        resource_key,
                    ),
                )
            acquired = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            self._append_audit(
                connection,
                resource_key=resource_key,
                task=task,
                holder=holder_id,
                fence=int(acquired["fence"]),
                event_type="lease_acquired" if row is None else "lease_taken_over",
                expires_at=acquired["expires_at"],
            )
            return _record(acquired)

    def renew(
        self,
        *,
        resource_key: str,
        project_id: str,
        task_id: str,
        holder: VerifiedPrincipal,
        fence: int,
        ttl_seconds: int,
    ) -> LeaseOperationResult:
        resource_key = _required_text(resource_key, "resource_key")
        project_id = _required_text(project_id, "project_id")
        task_id = _required_text(task_id, "task_id")
        fence = _positive_int(fence, "fence")
        ttl_seconds = _positive_int(ttl_seconds, "ttl_seconds")

        with self.store.transaction(immediate=True) as connection:
            holder_id = self._holder_id(connection, holder)
            row = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            self._require_match(
                connection,
                row,
                resource_key=resource_key,
                project_id=project_id,
                task_id=task_id,
                holder=holder_id,
                fence=fence,
                require_active=True,
            )
            expires_at = self._expires(connection, ttl_seconds)
            connection.execute(
                "UPDATE leases SET expires_at = ? WHERE resource_key = ? AND fence = ?",
                (expires_at, resource_key, fence),
            )
            renewed = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            task = self._assert_task_scope(connection, project_id, task_id)
            self._append_audit(
                connection,
                resource_key=resource_key,
                task=task,
                holder=holder_id,
                fence=fence,
                event_type="lease_renewed",
                expires_at=renewed["expires_at"],
            )
            return _record(renewed)

    def release(
        self,
        *,
        resource_key: str,
        project_id: str,
        task_id: str,
        holder: VerifiedPrincipal,
        fence: int,
    ) -> LeaseOperationResult:
        resource_key = _required_text(resource_key, "resource_key")
        project_id = _required_text(project_id, "project_id")
        task_id = _required_text(task_id, "task_id")
        fence = _positive_int(fence, "fence")

        with self.store.transaction(immediate=True) as connection:
            holder_id = self._holder_id(connection, holder)
            row = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            self._require_match(
                connection,
                row,
                resource_key=resource_key,
                project_id=project_id,
                task_id=task_id,
                holder=holder_id,
                fence=fence,
                require_active=False,
            )
            already_released = row["released_at"] is not None
            if not already_released:
                if not self._is_active(connection, row):
                    raise LeaseError(
                        f"lease has expired: {resource_key} at fence {fence}"
                    )
                connection.execute(
                    "UPDATE leases SET released_at = ? WHERE resource_key = ? AND fence = ?",
                    (self._now(connection), resource_key, fence),
                )
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
                ).fetchone()
                task = self._assert_task_scope(connection, project_id, task_id)
                self._append_audit(
                    connection,
                    resource_key=resource_key,
                    task=task,
                    holder=holder_id,
                    fence=fence,
                    event_type="lease_released",
                    expires_at=row["expires_at"],
                )
            return _record(row, replayed=already_released)

    def current_fence(self, resource_key: str) -> int | None:
        resource_key = _required_text(resource_key, "resource_key")
        rows = self.store.query(
            "SELECT fence FROM leases WHERE resource_key = ?", (resource_key,)
        )
        return int(rows[0]["fence"]) if rows else None

    def require_current_fence(
        self,
        *,
        resource_key: str,
        project_id: str,
        task_id: str,
        holder: VerifiedPrincipal,
        fence: int,
        require_active: bool = True,
    ) -> LeaseRecord:
        resource_key = _required_text(resource_key, "resource_key")
        project_id = _required_text(project_id, "project_id")
        task_id = _required_text(task_id, "task_id")
        fence = _positive_int(fence, "fence")
        with self.store.transaction() as connection:
            holder_id = self._holder_id(connection, holder)
            row = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            self._require_match(
                connection,
                row,
                resource_key=resource_key,
                project_id=project_id,
                task_id=task_id,
                holder=holder_id,
                fence=fence,
                require_active=require_active,
            )
            return _record(row)

    @classmethod
    def _require_match(
        cls,
        connection: Any,
        row: Any,
        *,
        resource_key: str,
        project_id: str,
        task_id: str,
        holder: str,
        fence: int,
        require_active: bool,
    ) -> None:
        if row is None:
            raise LeaseError(f"lease does not exist: {resource_key}")
        expected = (project_id, task_id, holder, fence)
        actual = (row["project_id"], row["task_id"], row["holder"], int(row["fence"]))
        if actual != expected:
            raise LeaseError(
                f"lease scope or fence mismatch for {resource_key}: "
                f"expected {expected}, found {actual}"
            )
        if require_active and not cls._is_active(connection, row):
            raise LeaseError(f"lease is not active: {resource_key} at fence {fence}")
