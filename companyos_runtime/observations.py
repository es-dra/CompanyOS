"""Fresh runtime-surface observations; documentation is never runtime truth."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from .errors import FreshnessError, NotFoundError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .store import SQLiteStore
from .types import GoalSpec, RuntimeSurfaceSpec, canonical_json, content_hash, utc_now


_HEALTHY = {"healthy", "ok", "pass"}
_VALID_STATUSES = _HEALTHY | {"degraded", "unhealthy", "failed", "unknown"}
_NON_PROBES = {"documentation", "readme", "static_doc", "declared_state"}
_DOCUMENT_SUFFIXES = (".md", ".markdown", ".rst", ".adoc", ".txt")


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FreshnessError(f"{field} must be a non-empty string")
    return value.strip()


def _instant(value: str | datetime | None, *, default_now: bool = False) -> datetime:
    if value is None:
        if default_now:
            return datetime.now(UTC)
        raise FreshnessError("timestamp is required")
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise FreshnessError(f"invalid ISO-8601 timestamp: {value}") from exc
    else:
        raise FreshnessError("timestamp must be a datetime or ISO-8601 string")
    if parsed.tzinfo is None:
        raise FreshnessError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class RuntimeObservation:
    observation_id: str
    project_id: str
    run_id: str
    surface_key: str
    target_identity: str
    observer: str
    probe_name: str
    probe_version: str
    status: str
    value: Mapping[str, Any]
    value_digest: str
    observed_at: str
    recorded_at: str
    expires_at: str
    trigger_event_id: str | None = None


class ObservationRegistry:
    """Records probes and evaluates freshness at the decision instant."""

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

    def record(
        self,
        *,
        project_id: str,
        run_id: str,
        surface_key: str,
        target_identity: str,
        observer: VerifiedPrincipal,
        probe_name: str,
        probe_version: str,
        status: str,
        value: Mapping[str, Any],
        ttl_seconds: int,
        observed_at: str | datetime | None = None,
        trigger_event_id: str | None = None,
        observation_id: str | None = None,
    ) -> RuntimeObservation:
        project_id = _text(project_id, "project_id")
        run_id = _text(run_id, "run_id")
        surface_key = _text(surface_key, "surface_key")
        target_identity = _text(target_identity, "target_identity")
        probe_name = _text(probe_name, "probe_name")
        probe_version = _text(probe_version, "probe_version")
        status = _text(status, "status").lower()
        if status not in _VALID_STATUSES:
            raise FreshnessError(f"unsupported observation status: {status}")
        normalized_probe = probe_name.lower().replace("\\", "/")
        if (
            normalized_probe in _NON_PROBES
            or normalized_probe.endswith(_DOCUMENT_SUFFIXES)
            or normalized_probe.rsplit("/", 1)[-1].startswith("readme.")
        ):
            raise FreshnessError(
                "documentation or declared state is not a runtime probe"
            )
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds < 1
        ):
            raise FreshnessError("ttl_seconds must be a positive integer")
        if not isinstance(value, Mapping):
            raise FreshnessError("value must be an object")
        observed = _instant(observed_at, default_now=True)
        now = datetime.now(UTC)
        if observed > now + timedelta(minutes=5):
            raise FreshnessError("observed_at is implausibly far in the future")
        expires = observed + timedelta(seconds=ttl_seconds)
        if expires <= now:
            raise FreshnessError("observation is already stale when recorded")
        observation_id = _text(observation_id or str(uuid.uuid4()), "observation_id")
        value_dict = dict(value)
        digest = content_hash(value_dict)
        observed_text = observed.isoformat(timespec="microseconds")
        recorded_text = utc_now()
        expires_text = expires.isoformat(timespec="microseconds")

        with self.store.transaction(immediate=True) as connection:
            observer_id = self.identity.require_role_in_transaction(
                connection, observer, Role.OBSERVER
            ).principal_id
            run = connection.execute(
                "SELECT project_id, goal_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None or run["project_id"] != project_id:
                raise NotFoundError(f"run not found in project: {project_id}/{run_id}")
            goal_row = connection.execute(
                "SELECT spec_json FROM goals WHERE goal_id = ? AND project_id = ?",
                (run["goal_id"], project_id),
            ).fetchone()
            if goal_row is None:
                raise FreshnessError("run goal contract is missing")
            goal = GoalSpec.from_dict(json.loads(goal_row["spec_json"]))
            requirements = {
                item.surface_key: item for item in goal.required_runtime_surfaces
            }
            requirement = requirements.get(surface_key)
            if requirement is None:
                raise FreshnessError("surface is not declared by the goal contract")
            if target_identity != requirement.target_identity:
                raise FreshnessError("target identity does not match the goal contract")
            if probe_name not in requirement.allowed_probes:
                raise FreshnessError("probe is not allowed by the goal contract")
            if ttl_seconds > requirement.max_ttl_seconds:
                raise FreshnessError("observation TTL exceeds the goal contract")
            if requirement.trigger_event_required and trigger_event_id is None:
                raise FreshnessError("a causal trigger event is required")
            if (
                trigger_event_id is not None
                and connection.execute(
                    "SELECT 1 FROM events WHERE event_id = ? AND run_id = ?",
                    (trigger_event_id, run_id),
                ).fetchone()
                is None
            ):
                raise FreshnessError(
                    "trigger event is missing or belongs to another run"
                )
            payload = {
                "surface_key": surface_key,
                "target_identity": target_identity,
                "observer": observer_id,
                "probe_name": probe_name,
                "probe_version": probe_version,
                "status": status,
                "value_digest": digest,
                "observed_at": observed_text,
                "expires_at": expires_text,
            }
            self.store.append_event(
                connection,
                aggregate_type="runtime_observation",
                aggregate_id=observation_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                event_type="runtime_observation_recorded",
                actor=observer_id,
                command_id=str(uuid.uuid4()),
                correlation_id=run_id,
                causation_id=trigger_event_id,
                policy_version=self.policy_version,
                payload=payload,
            )
            connection.execute(
                """
                INSERT INTO runtime_observations(
                    observation_id, project_id, run_id, surface_key,
                    target_identity, observer, probe_name, probe_version,
                    trigger_event_id, status, value_json, value_digest,
                    observed_at, recorded_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    project_id,
                    run_id,
                    surface_key,
                    target_identity,
                    observer_id,
                    probe_name,
                    probe_version,
                    trigger_event_id,
                    status,
                    canonical_json(value_dict),
                    digest,
                    observed_text,
                    recorded_text,
                    expires_text,
                ),
            )
        return RuntimeObservation(
            observation_id=observation_id,
            project_id=project_id,
            run_id=run_id,
            surface_key=surface_key,
            target_identity=target_identity,
            observer=observer_id,
            probe_name=probe_name,
            probe_version=probe_version,
            trigger_event_id=trigger_event_id,
            status=status,
            value=value_dict,
            value_digest=digest,
            observed_at=observed_text,
            recorded_at=recorded_text,
            expires_at=expires_text,
        )

    def require_fresh(
        self,
        *,
        run_id: str,
        required_surfaces: tuple[RuntimeSurfaceSpec, ...],
        as_of: str | datetime | None = None,
    ) -> dict[str, RuntimeObservation]:
        run_id = _text(run_id, "run_id")
        decision_time = _instant(as_of, default_now=True)
        result: dict[str, RuntimeObservation] = {}
        failures: list[str] = []
        for requirement in required_surfaces:
            if not isinstance(requirement, RuntimeSurfaceSpec):
                raise FreshnessError(
                    "required_surfaces must contain RuntimeSurfaceSpec"
                )
            key = requirement.surface_key
            rows = self.store.query(
                "SELECT * FROM runtime_observations WHERE run_id = ? AND surface_key = ? "
                "ORDER BY observed_at DESC, recorded_at DESC",
                (run_id, key),
            )
            if not rows:
                failures.append(f"{key}: missing")
                continue
            latest = rows[0]
            observed = _instant(latest["observed_at"])
            expires = _instant(latest["expires_at"])
            if observed > decision_time:
                failures.append(f"{key}: newest observation is future-dated")
                continue
            if expires <= decision_time:
                failures.append(f"{key}: stale since {latest['expires_at']}")
                continue
            if latest["status"] not in _HEALTHY:
                failures.append(f"{key}: status={latest['status']}")
                continue
            if latest["target_identity"] != requirement.target_identity:
                failures.append(
                    f"{key}: target identity {latest['target_identity']} != {requirement.target_identity}"
                )
                continue
            if latest["probe_name"] not in requirement.allowed_probes:
                failures.append(f"{key}: untrusted probe={latest['probe_name']}")
                continue
            ttl = (_instant(latest["expires_at"]) - observed).total_seconds()
            if ttl > requirement.max_ttl_seconds:
                failures.append(f"{key}: TTL exceeds contract")
                continue
            if (
                requirement.trigger_event_required
                and latest["trigger_event_id"] is None
            ):
                failures.append(f"{key}: missing causal trigger event")
                continue
            trusted_observer = self.store.query(
                "SELECT 1 FROM principals AS p JOIN principal_roles AS r "
                "ON r.principal_id = p.principal_id "
                "WHERE p.principal_id = ? AND p.enabled = 1 AND r.role = ?",
                (latest["observer"], Role.OBSERVER.value),
            )
            if not trusted_observer:
                failures.append(f"{key}: observer is not currently trusted")
                continue
            same_instant = [
                row for row in rows if row["observed_at"] == latest["observed_at"]
            ]
            signatures = {
                (row["target_identity"], row["status"], row["value_digest"])
                for row in same_instant
            }
            if len(signatures) > 1:
                failures.append(
                    f"{key}: contradictory observations at {latest['observed_at']}"
                )
                continue
            result[key] = RuntimeObservation(
                observation_id=latest["observation_id"],
                project_id=latest["project_id"],
                run_id=latest["run_id"],
                surface_key=latest["surface_key"],
                target_identity=latest["target_identity"],
                observer=latest["observer"],
                probe_name=latest["probe_name"],
                probe_version=latest["probe_version"],
                trigger_event_id=latest["trigger_event_id"],
                status=latest["status"],
                value=json.loads(latest["value_json"]),
                value_digest=latest["value_digest"],
                observed_at=latest["observed_at"],
                recorded_at=latest["recorded_at"],
                expires_at=latest["expires_at"],
            )
        if failures:
            raise FreshnessError(
                "runtime freshness gate failed: " + "; ".join(failures)
            )
        return result
