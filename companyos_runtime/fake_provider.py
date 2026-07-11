"""Zero-cost SQLite-backed provider double for crash/replay evaluation."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .adapters import AdapterReceipt
from .errors import IntegrityError
from .types import canonical_json, content_hash, utc_now


FakeProviderReceipt = AdapterReceipt


class FakeProvider:
    """Acts like an external idempotent service without network or provider cost."""

    _ADAPTER_ID = "fake-provider"

    def __init__(
        self,
        path: str | Path,
        *,
        legacy_project_migrations: Mapping[str, str] | None = None,
    ):
        self.path = Path(path).expanduser().resolve()
        self._legacy_project_migrations = dict(legacy_project_migrations or {})
        if any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(project, str)
            or not project.strip()
            or project.strip() == "__legacy__"
            for key, project in self._legacy_project_migrations.items()
        ):
            raise IntegrityError(
                "legacy project migrations require non-empty idempotency keys and project ids"
            )

    @property
    def adapter_id(self) -> str:
        """Stable identity compiled into every executable workflow step."""

        return self._ADAPTER_ID

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.transaction() as connection:
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(provider_effects)"
                ).fetchall()
            }
            if columns and "project_id" not in columns:
                connection.execute("DROP TABLE IF EXISTS provider_effects_v2")
                connection.execute(self._provider_effects_ddl("provider_effects_v2"))
                connection.execute(
                    """
                    INSERT INTO provider_effects_v2(
                        project_id, idempotency_key, effect_id, request_digest,
                        request_json, provider_receipt, status, result_json, created_at
                    )
                    SELECT '__legacy__', idempotency_key, effect_id, request_digest,
                           request_json, provider_receipt, status, result_json, created_at
                    FROM provider_effects
                    """
                )
                connection.execute("DROP TABLE provider_effects")
                connection.execute(
                    "ALTER TABLE provider_effects_v2 RENAME TO provider_effects"
                )
            elif not columns:
                connection.execute(self._provider_effects_ddl("provider_effects"))
            for idempotency_key, project_id in self._legacy_project_migrations.items():
                connection.execute(
                    "UPDATE provider_effects SET project_id = ? "
                    "WHERE project_id = '__legacy__' AND idempotency_key = ?",
                    (project_id.strip(), idempotency_key.strip()),
                )

    @staticmethod
    def _provider_effects_ddl(table_name: str) -> str:
        if table_name not in {"provider_effects", "provider_effects_v2"}:
            raise ValueError("unsupported fake-provider table name")
        return f"""
                CREATE TABLE {table_name}(
                    project_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    effect_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    provider_receipt TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(project_id, idempotency_key),
                    UNIQUE(project_id, effect_id)
                )
                """

    @staticmethod
    def _find_prior(
        connection: sqlite3.Connection, project_id: str, idempotency_key: str
    ) -> sqlite3.Row | None:
        prior = connection.execute(
            "SELECT * FROM provider_effects WHERE project_id = ? AND idempotency_key = ?",
            (project_id, idempotency_key),
        ).fetchone()
        return prior

    def execute(
        self,
        *,
        project_id: str,
        idempotency_key: str,
        effect_id: str,
        request_digest: str,
        request: Mapping[str, Any],
    ) -> FakeProviderReceipt:
        if not isinstance(project_id, str) or not project_id.strip():
            raise IntegrityError("fake-provider project_id must be non-empty")
        project_id = project_id.strip()
        if content_hash(dict(request)) != request_digest:
            raise IntegrityError("fake-provider request digest mismatch")
        with self.transaction() as connection:
            prior = self._find_prior(connection, project_id, idempotency_key)
            if prior is not None:
                return self._receipt(
                    prior,
                    project_id,
                    idempotency_key,
                    effect_id,
                    request_digest,
                    replayed=True,
                )
            operation = request.get("operation", "write")
            result: dict[str, Any]
            if operation == "fail":
                status = "failed"
                result = {
                    "error_class": str(request.get("error_class", "SyntheticFailure")),
                    "message": str(
                        request.get("message", "deterministic fake-provider failure")
                    ),
                }
            else:
                status = "succeeded"
                result = {
                    "accepted": True,
                    "operation": operation,
                    "output_digest": content_hash(
                        {"effect_id": effect_id, "request": dict(request)}
                    ),
                }
            provider_receipt = f"fake-{uuid.uuid4()}"
            connection.execute(
                """
                INSERT INTO provider_effects(
                    project_id, idempotency_key, effect_id, request_digest,
                    request_json, provider_receipt, status, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    idempotency_key,
                    effect_id,
                    request_digest,
                    canonical_json(dict(request)),
                    provider_receipt,
                    status,
                    canonical_json(result),
                    utc_now(),
                ),
            )
            return FakeProviderReceipt(
                adapter_id=self.adapter_id,
                project_id=project_id,
                idempotency_key=idempotency_key,
                effect_id=effect_id,
                request_digest=request_digest,
                provider_receipt=provider_receipt,
                status=status,
                closed=True,
                result=result,
                replayed=False,
            )

    def lookup(
        self,
        *,
        project_id: str,
        idempotency_key: str,
        effect_id: str,
        request_digest: str,
    ) -> FakeProviderReceipt | None:
        """Return an already-committed provider receipt without creating an effect."""

        if not isinstance(project_id, str) or not project_id.strip():
            raise IntegrityError("fake-provider project_id must be non-empty")
        project_id = project_id.strip()
        connection = self.connect()
        try:
            prior = self._find_prior(connection, project_id, idempotency_key)
            if prior is None:
                return None
            return self._receipt(
                prior,
                project_id,
                idempotency_key,
                effect_id,
                request_digest,
                replayed=True,
            )
        finally:
            connection.close()

    def _receipt(
        self,
        row: sqlite3.Row | Mapping[str, Any],
        project_id: str,
        idempotency_key: str,
        effect_id: str,
        request_digest: str,
        *,
        replayed: bool,
    ) -> FakeProviderReceipt:
        if (
            row["project_id"] != project_id
            or row["idempotency_key"] != idempotency_key
            or row["effect_id"] != effect_id
            or row["request_digest"] != request_digest
        ):
            raise IntegrityError(
                "fake-provider project/idempotency key reused with different effect"
            )
        return FakeProviderReceipt(
            adapter_id=self.adapter_id,
            project_id=project_id,
            idempotency_key=idempotency_key,
            effect_id=effect_id,
            request_digest=request_digest,
            provider_receipt=row["provider_receipt"],
            status=row["status"],
            closed=True,
            result=json.loads(row["result_json"]),
            replayed=replayed,
        )

    def effect_count(self, *, project_id: str | None = None) -> int:
        connection = self.connect()
        try:
            if project_id is None:
                row = connection.execute("SELECT COUNT(*) FROM provider_effects")
            else:
                row = connection.execute(
                    "SELECT COUNT(*) FROM provider_effects WHERE project_id = ?",
                    (project_id,),
                )
            return int(row.fetchone()[0])
        finally:
            connection.close()
