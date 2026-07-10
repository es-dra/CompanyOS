"""Durable context registration and policy-filtered assembly."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Protocol

from .errors import AuthorizationError, ContractError, IntegrityError, NotFoundError
from .scope import normalize_scope, scope_allowed, scopes_overlap
from .store import SQLiteStore
from .types import TaskSpec, canonical_json, content_hash, utc_now


KNOWN_CLASSIFICATIONS = frozenset(
    {"public", "publicable", "internal", "private", "confidential", "secret"}
)
ACTIVE_INSTRUCTION_CLASSIFICATIONS = frozenset({"public", "publicable", "internal"})
INSTRUCTION_STATUSES = frozenset({"active", "limited"})
AUTHORING_STATUSES = frozenset({"candidate", "draft"})
KNOWN_NORMATIVE_STATUSES = frozenset(
    {
        "active",
        "limited",
        "candidate",
        "draft",
        "historical_draft",
        "rejected",
        "retired",
    }
)


@dataclass(frozen=True, slots=True)
class TrustedSourceAttestation:
    """Verifier-bound envelope for importing normative context.

    ``proof`` is intentionally not persisted.  The injected verifier owns its
    interpretation (signature, identity assertion, or another future
    IdentityAuthority token); all authority-relevant record fields are bound
    exactly before that verifier is called.
    """

    attestation_id: str
    proof: str = field(repr=False)
    context_id: str
    project_id: str
    scope: str
    source_ref: str
    source_digest: str
    classification: str
    normative_status: str
    priority: int
    token_estimate: int
    observed_at: str
    effective_at: str
    expires_at: str | None
    supersedes: str | None
    policy_version: str


class TrustedSourceVerifier(Protocol):
    """Privileged composition-root boundary for normative context imports."""

    def verify(self, attestation: TrustedSourceAttestation) -> object | None:
        """Raise on denial and return None after authenticating the envelope."""


class DenyAllTrustedSourceVerifier:
    """Safe default until an IdentityAuthority-backed verifier is installed."""

    def verify(self, attestation: TrustedSourceAttestation) -> None:
        del attestation
        raise AuthorizationError(
            "trusted context import is disabled: no trusted source verifier configured"
        )


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")
    return value.strip()


def _instant(
    value: str | datetime | None, name: str, *, default: str | None = None
) -> str:
    if value is None:
        if default is None:
            raise ContractError(f"{name} is required")
        value = default
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
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


def _is_current(row: dict[str, Any], at: datetime) -> bool:
    effective = datetime.fromisoformat(row["effective_at"])
    if effective > at:
        return False
    expires_at = row["expires_at"]
    return expires_at is None or datetime.fromisoformat(expires_at) > at


class ContextRegistry:
    """Store context provenance and assemble only policy-eligible instructions."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        trusted_source_verifier: TrustedSourceVerifier | None = None,
    ):
        self.store = store
        self._trusted_source_verifier = (
            trusted_source_verifier or DenyAllTrustedSourceVerifier()
        )

    @staticmethod
    def _prepare_record(
        *,
        context_id: str,
        project_id: str,
        scope: str,
        source_ref: str,
        content: str,
        classification: str,
        normative_status: str,
        priority: int,
        token_estimate: int | None,
        observed_at: str | datetime | None,
        effective_at: str | datetime | None,
        expires_at: str | datetime | None,
        supersedes: str | None,
    ) -> dict[str, Any]:
        context_id = _text(context_id, "context_id")
        project_id = _text(project_id, "project_id")
        scope = normalize_scope(_text(scope, "scope"))
        source_ref = _text(source_ref, "source_ref")
        content = _text(content, "content")
        classification = _text(classification, "classification").lower()
        normative_status = _text(normative_status, "normative_status").lower()
        if classification not in KNOWN_CLASSIFICATIONS:
            raise ContractError(f"unsupported classification: {classification}")
        if normative_status not in KNOWN_NORMATIVE_STATUSES:
            raise ContractError(f"unsupported normative_status: {normative_status}")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise ContractError("priority must be an integer")
        if token_estimate is None:
            token_estimate = max(1, (len(content) + 3) // 4)
        if (
            isinstance(token_estimate, bool)
            or not isinstance(token_estimate, int)
            or token_estimate < 1
        ):
            raise ContractError("token_estimate must be a positive integer")

        now = utc_now()
        observed = _instant(observed_at, "observed_at", default=now)
        effective = _instant(effective_at, "effective_at", default=observed)
        expiry = _instant(expires_at, "expires_at") if expires_at is not None else None
        if expiry is not None and datetime.fromisoformat(
            expiry
        ) <= datetime.fromisoformat(effective):
            raise ContractError("expires_at must be later than effective_at")
        if supersedes is not None:
            supersedes = _text(supersedes, "supersedes")
            if supersedes == context_id:
                raise ContractError("a context item cannot supersede itself")

        return {
            "context_id": context_id,
            "project_id": project_id,
            "scope": scope,
            "source_ref": source_ref,
            "source_digest": content_hash(
                {"source_ref": source_ref, "content": content}
            ),
            "content": content,
            "classification": classification,
            "normative_status": normative_status,
            "priority": priority,
            "token_estimate": token_estimate,
            "observed_at": observed,
            "effective_at": effective,
            "expires_at": expiry,
            "supersedes": supersedes,
            "created_at": now,
        }

    @staticmethod
    def _attestation_fingerprint(attestation: TrustedSourceAttestation) -> str:
        envelope = asdict(attestation)
        envelope.pop("proof")
        return content_hash(envelope)

    def _validate_trusted_attestation(
        self,
        *,
        record: dict[str, Any],
        policy_version: str,
        attestation: TrustedSourceAttestation,
    ) -> None:
        if type(attestation) is not TrustedSourceAttestation:
            raise ContractError(
                "attestation must be a TrustedSourceAttestation, not a caller flag"
            )
        if _text(attestation.attestation_id, "attestation.attestation_id") != (
            attestation.attestation_id
        ):
            raise ContractError("attestation_id must already be canonical")
        if _text(attestation.proof, "attestation.proof") != attestation.proof:
            raise ContractError("attestation proof must already be canonical")

        expected = {
            key: record[key]
            for key in (
                "context_id",
                "project_id",
                "scope",
                "source_ref",
                "source_digest",
                "classification",
                "normative_status",
                "priority",
                "token_estimate",
                "observed_at",
                "effective_at",
                "expires_at",
                "supersedes",
            )
        }
        expected["policy_version"] = policy_version
        for field_name, expected_value in expected.items():
            actual_value = getattr(attestation, field_name)
            if (
                type(actual_value) is not type(expected_value)
                or actual_value != expected_value
            ):
                raise AuthorizationError(
                    f"trusted attestation does not exactly match imported {field_name}"
                )

        verification_result = self._trusted_source_verifier.verify(attestation)
        if verification_result is not None:
            raise AuthorizationError(
                "trusted source verifier must raise on denial and return None on success"
            )

    def _persist(
        self,
        *,
        record: dict[str, Any],
        actor: str,
        policy_version: str,
        command_id: str | None,
        correlation_id: str | None,
        event_type: str,
        attestation: TrustedSourceAttestation | None = None,
    ) -> dict[str, Any]:
        context_id = record["context_id"]
        project_id = record["project_id"]
        supersedes = record["supersedes"]
        policy_version = _text(policy_version, "policy_version")
        with self.store.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM context_items WHERE context_id = ?", (context_id,)
            ).fetchone()
            if existing is not None:
                current = dict(existing)
                comparable = {
                    key: value for key, value in record.items() if key != "created_at"
                }
                if all(current[key] == value for key, value in comparable.items()):
                    if attestation is not None:
                        trusted_event = connection.execute(
                            "SELECT event_id FROM events WHERE aggregate_type = ? "
                            "AND aggregate_id = ? AND event_type = ?",
                            ("context_item", context_id, "trusted_context_imported"),
                        ).fetchone()
                        if trusted_event is None:
                            raise IntegrityError(
                                "normative context exists without a trusted import event"
                            )
                    return current
                raise IntegrityError(
                    f"context_id already exists with different content: {context_id}"
                )
            if supersedes is not None:
                previous = connection.execute(
                    "SELECT project_id, scope FROM context_items WHERE context_id = ?",
                    (supersedes,),
                ).fetchone()
                if previous is None:
                    raise NotFoundError(
                        f"superseded context item does not exist: {supersedes}"
                    )
                if (
                    previous["project_id"] != project_id
                    or previous["scope"] != record["scope"]
                ):
                    raise ContractError(
                        "supersession requires the same project and scope"
                    )

            payload = {key: value for key, value in record.items() if key != "content"}
            if attestation is not None:
                payload.update(
                    {
                        "trusted_attestation_id": attestation.attestation_id,
                        "trusted_attestation_digest": self._attestation_fingerprint(
                            attestation
                        ),
                        "trusted_policy_version": attestation.policy_version,
                    }
                )
            event = self.store.append_event(
                connection,
                aggregate_type="context_item",
                aggregate_id=context_id,
                expected_version=0,
                project_id=project_id,
                event_type=event_type,
                actor=_text(actor, "actor"),
                command_id=command_id or str(uuid.uuid4()),
                correlation_id=correlation_id or context_id,
                policy_version=policy_version,
                confidentiality=record["classification"],
                payload=payload,
            )
            connection.execute(
                """
                INSERT INTO context_items(
                    context_id, project_id, scope, source_ref, source_digest,
                    content, classification, normative_status, priority,
                    token_estimate, observed_at, effective_at, expires_at,
                    supersedes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(record.values()),
            )
        return {**record, "event_id": event["event_id"]}

    def register(
        self,
        *,
        context_id: str,
        project_id: str,
        scope: str,
        source_ref: str,
        content: str,
        classification: str = "internal",
        normative_status: str = "candidate",
        priority: int = 0,
        token_estimate: int | None = None,
        observed_at: str | datetime | None = None,
        effective_at: str | datetime | None = None,
        expires_at: str | datetime | None = None,
        supersedes: str | None = None,
        actor: str = "context_registry",
        policy_version: str = "1",
        command_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        record = self._prepare_record(
            context_id=context_id,
            project_id=project_id,
            scope=scope,
            source_ref=source_ref,
            content=content,
            classification=classification,
            normative_status=normative_status,
            priority=priority,
            token_estimate=token_estimate,
            observed_at=observed_at,
            effective_at=effective_at,
            expires_at=expires_at,
            supersedes=supersedes,
        )
        if record["normative_status"] not in AUTHORING_STATUSES:
            raise AuthorizationError(
                "register accepts only candidate or draft context; normative "
                "states require import_trusted and a configured verifier"
            )
        return self._persist(
            record=record,
            actor=actor,
            policy_version=policy_version,
            command_id=command_id,
            correlation_id=correlation_id,
            event_type="context_item_registered",
        )

    def import_trusted(
        self,
        *,
        context_id: str,
        project_id: str,
        scope: str,
        source_ref: str,
        content: str,
        normative_status: str,
        attestation: TrustedSourceAttestation,
        policy_version: str,
        classification: str = "internal",
        priority: int = 0,
        token_estimate: int | None = None,
        observed_at: str | datetime | None = None,
        effective_at: str | datetime | None = None,
        expires_at: str | datetime | None = None,
        supersedes: str | None = None,
        actor: str = "context_registry",
        command_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Import active/limited context only through a fail-closed verifier."""

        policy_version = _text(policy_version, "policy_version")
        record = self._prepare_record(
            context_id=context_id,
            project_id=project_id,
            scope=scope,
            source_ref=source_ref,
            content=content,
            classification=classification,
            normative_status=normative_status,
            priority=priority,
            token_estimate=token_estimate,
            observed_at=observed_at,
            effective_at=effective_at,
            expires_at=expires_at,
            supersedes=supersedes,
        )
        if record["normative_status"] not in INSTRUCTION_STATUSES:
            raise AuthorizationError(
                "import_trusted accepts only active or limited normative context"
            )
        self._validate_trusted_attestation(
            record=record,
            policy_version=policy_version,
            attestation=attestation,
        )
        return self._persist(
            record=record,
            actor=actor,
            policy_version=policy_version,
            command_id=command_id,
            correlation_id=correlation_id,
            event_type="trusted_context_imported",
            attestation=attestation,
        )

    def assemble(
        self,
        *,
        assembly_id: str,
        project_id: str,
        run_id: str,
        task_id: str,
        scopes: Iterable[str],
        token_budget: int,
        as_of: str | datetime | None = None,
        allowed_classifications: Iterable[str] | None = None,
        actor: str = "context_registry",
        policy_version: str = "1",
    ) -> dict[str, Any]:
        assembly_id = _text(assembly_id, "assembly_id")
        project_id = _text(project_id, "project_id")
        run_id = _text(run_id, "run_id")
        task_id = _text(task_id, "task_id")
        if isinstance(scopes, str):
            raise ContractError(
                "scopes must be an iterable of scope strings, not one string"
            )
        requested_scopes = {normalize_scope(_text(item, "scope")) for item in scopes}
        if not requested_scopes:
            raise ContractError("scopes must not be empty")
        if (
            isinstance(token_budget, bool)
            or not isinstance(token_budget, int)
            or token_budget < 1
        ):
            raise ContractError("token_budget must be a positive integer")
        classification_source = (
            ACTIVE_INSTRUCTION_CLASSIFICATIONS
            if allowed_classifications is None
            else allowed_classifications
        )
        if isinstance(classification_source, str):
            raise ContractError(
                "allowed_classifications must be an iterable, not one string"
            )
        requested_classifications = {
            _text(item, "allowed_classification").lower()
            for item in classification_source
        }
        unknown = requested_classifications - KNOWN_CLASSIFICATIONS
        if unknown:
            raise ContractError(
                f"unsupported allowed classifications: {sorted(unknown)}"
            )
        effective_classifications = (
            requested_classifications & ACTIVE_INSTRUCTION_CLASSIFICATIONS
        )
        at_iso = _instant(as_of, "as_of", default=utc_now())
        at = datetime.fromisoformat(at_iso)

        with self.store.transaction(immediate=True) as connection:
            task = connection.execute(
                "SELECT project_id, run_id, spec_json FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            run = connection.execute(
                "SELECT project_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if task is None or run is None:
                raise NotFoundError(
                    "context assembly requires an existing run and task"
                )
            if (
                task["project_id"] != project_id
                or run["project_id"] != project_id
                or task["run_id"] != run_id
            ):
                raise ContractError(
                    "project, run, and task do not belong to the same execution"
                )
            try:
                task_spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
            except Exception as exc:
                raise ContractError(
                    "task has no valid compiled context authority"
                ) from exc
            unauthorized = [
                scope
                for scope in requested_scopes
                if not scope_allowed(task_spec.read_scope, scope)
            ]
            if unauthorized:
                raise ContractError(
                    f"requested context scopes exceed TaskSpec read_scope: {unauthorized}"
                )

            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM context_items WHERE project_id = ? "
                    "ORDER BY priority DESC, effective_at DESC, context_id ASC",
                    (project_id,),
                ).fetchall()
            ]
            by_id = {row["context_id"]: row for row in rows}
            trusted_context_ids: set[str] = set()
            trusted_events = connection.execute(
                "SELECT aggregate_id, policy_version, payload_json FROM events "
                "WHERE project_id = ? AND aggregate_type = ? AND event_type = ?",
                (project_id, "context_item", "trusted_context_imported"),
            ).fetchall()
            attested_fields = (
                "context_id",
                "project_id",
                "scope",
                "source_ref",
                "source_digest",
                "classification",
                "normative_status",
                "priority",
                "token_estimate",
                "observed_at",
                "effective_at",
                "expires_at",
                "supersedes",
            )
            for trusted_event in trusted_events:
                row = by_id.get(trusted_event["aggregate_id"])
                if row is None:
                    continue
                try:
                    payload = json.loads(trusted_event["payload_json"])
                    attestation_id = payload["trusted_attestation_id"]
                    attestation_digest = payload["trusted_attestation_digest"]
                    trusted_policy_version = payload["trusted_policy_version"]
                except (KeyError, TypeError, json.JSONDecodeError):
                    continue
                if (
                    not isinstance(attestation_id, str)
                    or not attestation_id.strip()
                    or not isinstance(attestation_digest, str)
                    or trusted_event["policy_version"] != trusted_policy_version
                    or any(
                        payload.get(field_name) != row[field_name]
                        for field_name in attested_fields
                    )
                ):
                    continue
                envelope = {
                    "attestation_id": attestation_id,
                    **{field_name: row[field_name] for field_name in attested_fields},
                    "policy_version": trusted_policy_version,
                }
                if content_hash(envelope) == attestation_digest:
                    trusted_context_ids.add(row["context_id"])

            superseded_by: dict[str, str] = {}
            for successor in rows:
                target_id = successor["supersedes"]
                target = by_id.get(target_id)
                if (
                    target is not None
                    and target["scope"] == successor["scope"]
                    and successor["normative_status"] in INSTRUCTION_STATUSES
                    and successor["context_id"] in trusted_context_ids
                    and _is_current(successor, at)
                ):
                    superseded_by.setdefault(target_id, successor["context_id"])

            selected: list[dict[str, Any]] = []
            rejected: list[dict[str, Any]] = []
            used_tokens = 0
            for row in rows:
                reason: str | None = None
                if (
                    content_hash(
                        {"source_ref": row["source_ref"], "content": row["content"]}
                    )
                    != row["source_digest"]
                ):
                    reason = "source_digest_mismatch"
                elif (
                    row["normative_status"] in INSTRUCTION_STATUSES
                    and row["context_id"] not in trusted_context_ids
                ):
                    reason = "untrusted_normative_source"
                elif not any(
                    scopes_overlap(row["scope"], requested)
                    for requested in requested_scopes
                ):
                    reason = "out_of_scope"
                elif row["normative_status"] not in INSTRUCTION_STATUSES:
                    reason = f"normative_status:{row['normative_status']}"
                elif datetime.fromisoformat(row["effective_at"]) > at:
                    reason = "not_effective"
                elif (
                    row["expires_at"] is not None
                    and datetime.fromisoformat(row["expires_at"]) <= at
                ):
                    reason = "expired"
                elif row["context_id"] in superseded_by:
                    reason = f"superseded_by:{superseded_by[row['context_id']]}"
                elif row["classification"] not in effective_classifications:
                    reason = (
                        "private_classification"
                        if row["classification"]
                        in {"private", "confidential", "secret"}
                        else "classification_not_allowed"
                    )
                elif used_tokens + row["token_estimate"] > token_budget:
                    reason = "token_budget"

                trace_item = {
                    "context_id": row["context_id"],
                    "scope": row["scope"],
                    "source_ref": row["source_ref"],
                    "source_digest": row["source_digest"],
                    "classification": row["classification"],
                    "normative_status": row["normative_status"],
                    "priority": row["priority"],
                    "token_estimate": row["token_estimate"],
                }
                if reason is not None:
                    rejected.append({**trace_item, "reason": reason})
                    continue
                selected.append({**trace_item, "content": row["content"]})
                used_tokens += row["token_estimate"]

            trace = {
                "assembly_id": assembly_id,
                "project_id": project_id,
                "run_id": run_id,
                "task_id": task_id,
                "as_of": at_iso,
                "scopes": sorted(requested_scopes),
                "allowed_classifications": sorted(effective_classifications),
                "token_budget": token_budget,
                "used_tokens": used_tokens,
                "selected": selected,
                "rejected": rejected,
            }
            assembly_digest = content_hash(trace)
            existing = connection.execute(
                "SELECT * FROM context_assemblies WHERE assembly_id = ?", (assembly_id,)
            ).fetchone()
            if existing is not None:
                if existing["assembly_digest"] != assembly_digest:
                    raise IntegrityError(
                        f"assembly_id reused for a different assembly: {assembly_id}"
                    )
                return {**trace, "assembly_digest": assembly_digest}

            event = self.store.append_event(
                connection,
                aggregate_type="context_assembly",
                aggregate_id=assembly_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                task_id=task_id,
                event_type="context_assembled",
                actor=_text(actor, "actor"),
                command_id=str(uuid.uuid4()),
                correlation_id=run_id,
                policy_version=_text(policy_version, "policy_version"),
                payload={
                    "assembly_digest": assembly_digest,
                    "selected_ids": [item["context_id"] for item in selected],
                    "rejected": [
                        {"context_id": item["context_id"], "reason": item["reason"]}
                        for item in rejected
                    ],
                },
            )
            connection.execute(
                "INSERT INTO context_assemblies(assembly_id, project_id, run_id, task_id, "
                "token_budget, selected_json, rejected_json, assembly_digest, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    assembly_id,
                    project_id,
                    run_id,
                    task_id,
                    token_budget,
                    canonical_json(selected),
                    canonical_json(rejected),
                    assembly_digest,
                    utc_now(),
                ),
            )
        return {
            **trace,
            "assembly_digest": assembly_digest,
            "event_id": event["event_id"],
        }

    def get_assembly(self, assembly_id: str) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT * FROM context_assemblies WHERE assembly_id = ?",
            (_text(assembly_id, "assembly_id"),),
        )
        if not rows:
            raise NotFoundError(f"context assembly does not exist: {assembly_id}")
        result = rows[0]
        result["selected"] = json.loads(result.pop("selected_json"))
        result["rejected"] = json.loads(result.pop("rejected_json"))
        return result
