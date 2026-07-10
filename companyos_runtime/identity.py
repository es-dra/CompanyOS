"""Persistent, fail-closed identity boundary for a single-host runtime.

This module authenticates local principals; it does not claim protection from
an administrator who can read the runtime process or rewrite its SQLite file.
Those process and database administrators are deliberately outside this trust
boundary. Credentials and bearer session secrets are never persisted in clear
text and are never written to the event log.

``VerifiedPrincipal`` is a short-lived bearer session, not an authorization
cache. Every privileged operation revalidates its secret digest, expiry,
credential version, enabled state, and current role membership in SQLite.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from .errors import AuthorizationError
from .store import SQLiteStore

PBKDF2_ITERATIONS: Final = 600_000
DEFAULT_SESSION_TTL_SECONDS: Final = 300
MAX_SESSION_TTL_SECONDS: Final = 900
_MINIMUM_CREDENTIAL_BYTES: Final = 12
_MAXIMUM_CREDENTIAL_BYTES: Final = 4096
_CONSTRUCTION_KEY: Final = object()
_DUMMY_SALT: Final = bytes.fromhex("824a301792846f8288cae338da717ccd")
_DUMMY_HASH: Final = bytes(32)


class Role(StrEnum):
    """Explicit roles understood by the local identity boundary."""

    OWNER = "owner"
    WORKER = "worker"
    EVALUATOR = "evaluator"
    RELEASE = "release"
    OBSERVER = "observer"
    PROVIDER_ATTESTOR = "provider_attestor"
    HUMAN_ACCEPTOR = "human_acceptor"
    BUSINESS_REVIEWER = "business_reviewer"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class PrincipalRecord:
    """Non-secret current principal projection returned after verification."""

    principal_id: str
    display_name: str
    roles: frozenset[Role]
    enabled: bool
    credential_version: int


class VerifiedPrincipal:
    """Opaque, short-lived authenticated session.

    Instances can only be issued by :class:`IdentityManager` through the normal
    constructor. More importantly, callers cannot authorize themselves by
    manufacturing or modifying an object: ``verify`` and ``require_role``
    validate its bearer proof against the persisted session on every use.
    """

    __slots__ = (
        "_display_name",
        "_expires_at",
        "_issued_at",
        "_principal_id",
        "_session_id",
        "_session_secret",
    )

    def __init__(
        self,
        construction_key: object,
        *,
        principal_id: str,
        display_name: str,
        session_id: str,
        session_secret: bytes,
        issued_at: str,
        expires_at: str,
    ) -> None:
        if construction_key is not _CONSTRUCTION_KEY:
            raise TypeError("VerifiedPrincipal sessions are issued by IdentityManager")
        self._principal_id = principal_id
        self._display_name = display_name
        self._session_id = session_id
        self._session_secret = session_secret
        self._issued_at = issued_at
        self._expires_at = expires_at

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def issued_at(self) -> str:
        return self._issued_at

    @property
    def expires_at(self) -> str:
        return self._expires_at

    def __repr__(self) -> str:
        return (
            "VerifiedPrincipal("
            f"principal_id={self.principal_id!r}, "
            f"display_name={self.display_name!r}, "
            f"session_id={self.session_id!r}, "
            f"expires_at={self.expires_at!r})"
        )

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("authenticated sessions cannot be serialized")


class IdentityManager:
    """Manage durable local principals and short-lived authenticated sessions."""

    def __init__(self, store: SQLiteStore):
        self.store = store

    def bootstrap_owner(
        self,
        *,
        display_name: str,
        credential: str | bytes,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> VerifiedPrincipal:
        """Perform one-time trust-on-first-use owner bootstrap.

        Bootstrap succeeds only while the complete principal registry is empty.
        A disabled or otherwise unusable registry is not considered empty and
        cannot be reset through this API.
        """

        principal_key, normalized_name = _principal_name(display_name)
        credential_bytes = _credential_bytes(credential, require_strength=True)
        ttl = _session_ttl(session_ttl_seconds)
        salt = secrets.token_bytes(16)
        digest = _derive_credential(credential_bytes, salt, PBKDF2_ITERATIONS)
        now = _utc_now()
        principal_id = str(uuid.uuid4())

        with self.store.transaction(immediate=True) as connection:
            count = connection.execute("SELECT COUNT(*) FROM principals").fetchone()[0]
            if int(count) != 0:
                raise AuthorizationError("owner bootstrap is closed")
            connection.execute(
                """
                INSERT INTO principals(
                    principal_id, principal_key, display_name, credential_salt,
                    credential_hash, credential_iterations, credential_version,
                    enabled, created_at, updated_at, disabled_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, NULL)
                """,
                (
                    principal_id,
                    principal_key,
                    normalized_name,
                    salt,
                    digest,
                    PBKDF2_ITERATIONS,
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO principal_roles(principal_id, role, granted_at) "
                "VALUES (?, ?, ?)",
                (principal_id, Role.OWNER.value, now),
            )
            return self._issue_session(
                connection,
                principal_id=principal_id,
                display_name=normalized_name,
                credential_version=1,
                ttl_seconds=ttl,
            )

    def authenticate(
        self,
        *,
        display_name: str,
        credential: str | bytes,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> VerifiedPrincipal:
        """Authenticate an enabled principal and issue a short-lived session."""

        principal_key, _ = _principal_name(display_name)
        credential_bytes = _credential_bytes(credential, require_strength=False)
        ttl = _session_ttl(session_ttl_seconds)

        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM principals WHERE principal_key = ?", (principal_key,)
            ).fetchone()
            salt = bytes(row["credential_salt"]) if row else _DUMMY_SALT
            iterations = int(row["credential_iterations"]) if row else PBKDF2_ITERATIONS
            expected = bytes(row["credential_hash"]) if row else _DUMMY_HASH
            candidate = _derive_credential(credential_bytes, salt, iterations)
            valid_credential = hmac.compare_digest(candidate, expected)
            if row is None or not valid_credential or int(row["enabled"]) != 1:
                raise AuthorizationError("invalid principal or credential")
            return self._issue_session(
                connection,
                principal_id=str(row["principal_id"]),
                display_name=str(row["display_name"]),
                credential_version=int(row["credential_version"]),
                ttl_seconds=ttl,
            )

    def verify(self, session: VerifiedPrincipal) -> PrincipalRecord:
        """Revalidate an authenticated session without granting a role."""

        with self.store.transaction() as connection:
            return self._verify_session(connection, session)

    def require_role(
        self, session: VerifiedPrincipal, required_role: Role | str
    ) -> PrincipalRecord:
        """Return the live principal projection only when the exact role exists.

        Owner is intentionally not an implicit substitute for maker/checker,
        attestor, acceptance, business-review, or release roles.
        """

        role = _role(required_role)
        with self.store.transaction() as connection:
            return self._verify_session(connection, session, required_role=role)

    def verify_in_transaction(
        self, connection: sqlite3.Connection, session: VerifiedPrincipal
    ) -> PrincipalRecord:
        """Revalidate a bearer inside the caller's already-open transaction.

        Privileged command handlers use this form so authorization and mutation
        share one SQLite serialization boundary. Passing a connection that has
        not begun a transaction is rejected to avoid reintroducing an auth/use
        race through a seemingly safe helper.
        """

        if not connection.in_transaction:
            raise AuthorizationError(
                "transaction-bound identity verification requires an active transaction"
            )
        return self._verify_session(connection, session)

    def require_role_in_transaction(
        self,
        connection: sqlite3.Connection,
        session: VerifiedPrincipal,
        required_role: Role | str,
    ) -> PrincipalRecord:
        """Require an exact live role in the caller's active transaction."""

        if not connection.in_transaction:
            raise AuthorizationError(
                "transaction-bound role verification requires an active transaction"
            )
        return self._verify_session(
            connection, session, required_role=_role(required_role)
        )

    def create_principal(
        self,
        owner_session: VerifiedPrincipal,
        *,
        display_name: str,
        credential: str | bytes,
        roles: Role
        | str
        | set[Role | str]
        | frozenset[Role | str]
        | tuple[Role | str, ...],
    ) -> PrincipalRecord:
        """Create an enabled principal; a currently verified owner is required."""

        principal_key, normalized_name = _principal_name(display_name)
        credential_bytes = _credential_bytes(credential, require_strength=True)
        normalized_roles = _roles(roles)
        salt = secrets.token_bytes(16)
        digest = _derive_credential(credential_bytes, salt, PBKDF2_ITERATIONS)
        now = _utc_now()
        principal_id = str(uuid.uuid4())

        with self.store.transaction(immediate=True) as connection:
            self._verify_session(connection, owner_session, required_role=Role.OWNER)
            try:
                connection.execute(
                    """
                    INSERT INTO principals(
                        principal_id, principal_key, display_name, credential_salt,
                        credential_hash, credential_iterations, credential_version,
                        enabled, created_at, updated_at, disabled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, NULL)
                    """,
                    (
                        principal_id,
                        principal_key,
                        normalized_name,
                        salt,
                        digest,
                        PBKDF2_ITERATIONS,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("principal already exists") from exc
            connection.executemany(
                "INSERT INTO principal_roles(principal_id, role, granted_at) "
                "VALUES (?, ?, ?)",
                [
                    (principal_id, role.value, now)
                    for role in sorted(normalized_roles, key=lambda item: item.value)
                ],
            )
            return self._principal_record(connection, principal_id)

    def set_roles(
        self,
        owner_session: VerifiedPrincipal,
        *,
        display_name: str,
        roles: Role
        | str
        | set[Role | str]
        | frozenset[Role | str]
        | tuple[Role | str, ...],
    ) -> PrincipalRecord:
        """Replace a principal's roles while preserving an enabled owner."""

        principal_key, _ = _principal_name(display_name)
        normalized_roles = _roles(roles)
        with self.store.transaction(immediate=True) as connection:
            self._verify_session(connection, owner_session, required_role=Role.OWNER)
            target = self._principal_by_key(connection, principal_key)
            current_roles = self._role_set(connection, str(target["principal_id"]))
            if (
                int(target["enabled"]) == 1
                and Role.OWNER in current_roles
                and Role.OWNER not in normalized_roles
            ):
                self._assert_not_last_enabled_owner(connection)
            now = _utc_now()
            connection.execute(
                "DELETE FROM principal_roles WHERE principal_id = ?",
                (target["principal_id"],),
            )
            connection.executemany(
                "INSERT INTO principal_roles(principal_id, role, granted_at) "
                "VALUES (?, ?, ?)",
                [
                    (target["principal_id"], role.value, now)
                    for role in sorted(normalized_roles, key=lambda item: item.value)
                ],
            )
            connection.execute(
                "UPDATE principals SET updated_at = ? WHERE principal_id = ?",
                (now, target["principal_id"]),
            )
            return self._principal_record(connection, str(target["principal_id"]))

    def disable_principal(
        self, owner_session: VerifiedPrincipal, *, display_name: str
    ) -> PrincipalRecord:
        """Disable a principal and revoke every outstanding session."""

        principal_key, _ = _principal_name(display_name)
        with self.store.transaction(immediate=True) as connection:
            self._verify_session(connection, owner_session, required_role=Role.OWNER)
            target = self._principal_by_key(connection, principal_key)
            target_id = str(target["principal_id"])
            roles = self._role_set(connection, target_id)
            if int(target["enabled"]) == 1 and Role.OWNER in roles:
                self._assert_not_last_enabled_owner(connection)
            now = _utc_now()
            connection.execute(
                """
                UPDATE principals
                SET enabled = 0, disabled_at = ?, updated_at = ?
                WHERE principal_id = ?
                """,
                (now, now, target_id),
            )
            connection.execute(
                """
                UPDATE authenticated_sessions SET revoked_at = ?
                WHERE principal_id = ? AND revoked_at IS NULL
                """,
                (now, target_id),
            )
            return self._principal_record(connection, target_id)

    def enable_principal(
        self, owner_session: VerifiedPrincipal, *, display_name: str
    ) -> PrincipalRecord:
        """Re-enable a principal; previously issued sessions remain revoked."""

        principal_key, _ = _principal_name(display_name)
        with self.store.transaction(immediate=True) as connection:
            self._verify_session(connection, owner_session, required_role=Role.OWNER)
            target = self._principal_by_key(connection, principal_key)
            now = _utc_now()
            connection.execute(
                """
                UPDATE principals
                SET enabled = 1, disabled_at = NULL, updated_at = ?
                WHERE principal_id = ?
                """,
                (now, target["principal_id"]),
            )
            return self._principal_record(connection, str(target["principal_id"]))

    def rotate_credential(
        self,
        session: VerifiedPrincipal,
        *,
        current_credential: str | bytes,
        new_credential: str | bytes,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> VerifiedPrincipal:
        """Rotate the authenticated principal's credential and all sessions."""

        current_bytes = _credential_bytes(current_credential, require_strength=False)
        new_bytes = _credential_bytes(new_credential, require_strength=True)
        ttl = _session_ttl(session_ttl_seconds)
        new_salt = secrets.token_bytes(16)
        new_digest = _derive_credential(new_bytes, new_salt, PBKDF2_ITERATIONS)

        with self.store.transaction(immediate=True) as connection:
            principal = self._verify_session(connection, session)
            row = connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?",
                (principal.principal_id,),
            ).fetchone()
            current_digest = _derive_credential(
                current_bytes,
                bytes(row["credential_salt"]),
                int(row["credential_iterations"]),
            )
            if not hmac.compare_digest(current_digest, bytes(row["credential_hash"])):
                raise AuthorizationError("invalid principal or credential")
            now = _utc_now()
            next_version = int(row["credential_version"]) + 1
            connection.execute(
                """
                UPDATE principals
                SET credential_salt = ?, credential_hash = ?,
                    credential_iterations = ?, credential_version = ?, updated_at = ?
                WHERE principal_id = ? AND enabled = 1
                """,
                (
                    new_salt,
                    new_digest,
                    PBKDF2_ITERATIONS,
                    next_version,
                    now,
                    principal.principal_id,
                ),
            )
            connection.execute(
                """
                UPDATE authenticated_sessions SET revoked_at = ?
                WHERE principal_id = ? AND revoked_at IS NULL
                """,
                (now, principal.principal_id),
            )
            return self._issue_session(
                connection,
                principal_id=principal.principal_id,
                display_name=principal.display_name,
                credential_version=next_version,
                ttl_seconds=ttl,
            )

    def revoke_session(self, session: VerifiedPrincipal) -> None:
        """Revoke a currently valid bearer session."""

        with self.store.transaction(immediate=True) as connection:
            self._verify_session(connection, session)
            connection.execute(
                "UPDATE authenticated_sessions SET revoked_at = ? WHERE session_id = ?",
                (_utc_now(), session.session_id),
            )

    def _issue_session(
        self,
        connection: sqlite3.Connection,
        *,
        principal_id: str,
        display_name: str,
        credential_version: int,
        ttl_seconds: int,
    ) -> VerifiedPrincipal:
        session_id = str(uuid.uuid4())
        session_secret = secrets.token_bytes(32)
        token_hash = hashlib.sha256(session_secret).digest()
        issued = datetime.now(UTC)
        expires = issued + timedelta(seconds=ttl_seconds)
        issued_at = _format_instant(issued)
        expires_at = _format_instant(expires)
        connection.execute(
            """
            INSERT INTO authenticated_sessions(
                session_id, principal_id, session_token_hash,
                credential_version, issued_at, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                session_id,
                principal_id,
                token_hash,
                credential_version,
                issued_at,
                expires_at,
            ),
        )
        return VerifiedPrincipal(
            _CONSTRUCTION_KEY,
            principal_id=principal_id,
            display_name=display_name,
            session_id=session_id,
            session_secret=session_secret,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def _verify_session(
        self,
        connection: sqlite3.Connection,
        session: VerifiedPrincipal,
        *,
        required_role: Role | None = None,
    ) -> PrincipalRecord:
        if not isinstance(session, VerifiedPrincipal):
            raise AuthorizationError("authenticated session is required")
        try:
            session_id = object.__getattribute__(session, "_session_id")
            session_secret = object.__getattribute__(session, "_session_secret")
            object_principal_id = object.__getattribute__(session, "_principal_id")
            object_display_name = object.__getattribute__(session, "_display_name")
        except (AttributeError, TypeError) as exc:
            raise AuthorizationError(
                "authenticated session is invalid or expired"
            ) from exc
        if not isinstance(session_id, str) or not isinstance(session_secret, bytes):
            raise AuthorizationError("authenticated session is invalid or expired")

        row = connection.execute(
            """
            SELECT
                s.session_id, s.principal_id, s.session_token_hash,
                s.credential_version AS session_credential_version,
                s.expires_at, s.revoked_at,
                p.display_name, p.enabled,
                p.credential_version AS principal_credential_version
            FROM authenticated_sessions AS s
            JOIN principals AS p ON p.principal_id = s.principal_id
            WHERE s.session_id = ?
            """,
            (session_id,),
        ).fetchone()
        token_hash = hashlib.sha256(session_secret).digest()
        valid = (
            row is not None
            and hmac.compare_digest(token_hash, bytes(row["session_token_hash"]))
            and row["revoked_at"] is None
            and int(row["enabled"]) == 1
            and int(row["session_credential_version"])
            == int(row["principal_credential_version"])
            and str(row["expires_at"]) > _utc_now()
            and str(row["principal_id"]) == object_principal_id
            and str(row["display_name"]) == object_display_name
        )
        if not valid:
            raise AuthorizationError("authenticated session is invalid or expired")

        principal_id = str(row["principal_id"])
        roles = self._role_set(connection, principal_id)
        if required_role is not None and required_role not in roles:
            raise AuthorizationError(f"required role is missing: {required_role.value}")
        if not roles:
            raise AuthorizationError("principal has no authorized role")
        return PrincipalRecord(
            principal_id=principal_id,
            display_name=str(row["display_name"]),
            roles=roles,
            enabled=True,
            credential_version=int(row["principal_credential_version"]),
        )

    @staticmethod
    def _principal_by_key(
        connection: sqlite3.Connection, principal_key: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM principals WHERE principal_key = ?", (principal_key,)
        ).fetchone()
        if row is None:
            raise AuthorizationError("principal does not exist")
        return row

    def _principal_record(
        self, connection: sqlite3.Connection, principal_id: str
    ) -> PrincipalRecord:
        row = connection.execute(
            "SELECT * FROM principals WHERE principal_id = ?", (principal_id,)
        ).fetchone()
        if row is None:
            raise AuthorizationError("principal does not exist")
        return PrincipalRecord(
            principal_id=principal_id,
            display_name=str(row["display_name"]),
            roles=self._role_set(connection, principal_id),
            enabled=bool(row["enabled"]),
            credential_version=int(row["credential_version"]),
        )

    @staticmethod
    def _role_set(connection: sqlite3.Connection, principal_id: str) -> frozenset[Role]:
        rows = connection.execute(
            "SELECT role FROM principal_roles WHERE principal_id = ?",
            (principal_id,),
        ).fetchall()
        return frozenset(Role(str(row["role"])) for row in rows)

    @staticmethod
    def _assert_not_last_enabled_owner(connection: sqlite3.Connection) -> None:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM principals AS p
            JOIN principal_roles AS r ON r.principal_id = p.principal_id
            WHERE p.enabled = 1 AND r.role = ?
            """,
            (Role.OWNER.value,),
        ).fetchone()[0]
        if int(count) <= 1:
            raise AuthorizationError("the last enabled owner cannot be removed")


def _principal_name(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise TypeError("display_name must be a string")
    normalized = unicodedata.normalize("NFKC", value.strip())
    if not normalized or len(normalized) > 128:
        raise ValueError("display_name must contain 1 to 128 characters")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise ValueError("display_name cannot contain control characters")
    return normalized.casefold(), normalized


def _credential_bytes(value: str | bytes, *, require_strength: bool) -> bytes:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise TypeError("credential must be text or bytes")
    minimum = _MINIMUM_CREDENTIAL_BYTES if require_strength else 1
    if len(raw) < minimum or len(raw) > _MAXIMUM_CREDENTIAL_BYTES:
        if require_strength:
            raise ValueError(
                f"credential must contain {_MINIMUM_CREDENTIAL_BYTES} to "
                f"{_MAXIMUM_CREDENTIAL_BYTES} UTF-8 bytes"
            )
        raise AuthorizationError("invalid principal or credential")
    return raw


def _derive_credential(credential: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", credential, salt, iterations, dklen=32)


def _role(value: Role | str) -> Role:
    try:
        return value if isinstance(value, Role) else Role(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unknown principal role: {value!r}") from exc


def _roles(
    values: Role
    | str
    | set[Role | str]
    | frozenset[Role | str]
    | tuple[Role | str, ...],
) -> frozenset[Role]:
    raw_values = (values,) if isinstance(values, (Role, str)) else tuple(values)
    normalized = frozenset(_role(value) for value in raw_values)
    if not normalized:
        raise ValueError("at least one role is required")
    return normalized


def _session_ttl(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("session_ttl_seconds must be an integer")
    if value <= 0 or value > MAX_SESSION_TTL_SECONDS:
        raise ValueError(
            f"session_ttl_seconds must be between 1 and {MAX_SESSION_TTL_SECONDS}"
        )
    return value


def _utc_now() -> str:
    return _format_instant(datetime.now(UTC))


def _format_instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")
