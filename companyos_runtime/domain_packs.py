"""AOS Core v0.1 object boundary and deterministic Domain Pack harness."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .compiler import compile_goal, compile_task
from .errors import ContractError, IntegrityError
from .scope import validate_task_within_goal
from .types import GoalSpec, TaskSpec, content_hash


CORE_CONTRACT_VERSION = "aos.core.v0.1"
_FIXTURE_FIELDS = frozenset(
    {
        "pack_id",
        "pack_version",
        "domain",
        "domain_ref",
        "goal_authoring",
        "task_authoring",
    }
)
_BUNDLE_FIELDS = frozenset(
    {
        "contract_version",
        "domain_pack",
        "domain_ref",
        "goal_spec",
        "task_spec",
        "source_digests",
    }
)


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    return value


def _exact_fields(value: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    missing = fields - value.keys()
    unknown = value.keys() - fields
    if missing:
        raise ContractError(f"{label} missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unknown fields: {sorted(unknown)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    return value.strip()


def _pack_id(value: Any) -> str:
    result = _text(value, "pack_id")
    if any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in result
    ):
        raise ContractError("pack_id must use lowercase letters, digits, and hyphens")
    return result


def _digest(value: Any, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise ContractError(f"{label} must be lowercase SHA-256 hex")
    return result


class DomainPack(Protocol):
    """The only API a domain implements to target AOS Core v0.1."""

    @property
    def pack_id(self) -> str: ...

    @property
    def pack_version(self) -> str: ...

    @property
    def domain(self) -> str: ...

    @property
    def domain_ref(self) -> str: ...

    def goal_authoring(self) -> Mapping[str, Any]: ...

    def task_authoring(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class FixtureDomainPack:
    """Static deterministic adapter for conformance fixtures and local trials."""

    pack_id: str
    pack_version: str
    domain: str
    domain_ref: str
    _goal_authoring: Mapping[str, Any]
    _task_authoring: Mapping[str, Any]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FixtureDomainPack":
        _exact_fields(data, _FIXTURE_FIELDS, "domain pack fixture")
        pack_id = _pack_id(data["pack_id"])
        domain_ref = _text(data["domain_ref"], "domain_ref")
        if not domain_ref.startswith(f"domain://{pack_id}/"):
            raise ContractError("domain_ref must be an opaque URI owned by pack_id")
        return cls(
            pack_id=pack_id,
            pack_version=_text(data["pack_version"], "pack_version"),
            domain=_text(data["domain"], "domain"),
            domain_ref=domain_ref,
            _goal_authoring=deepcopy(_object(data["goal_authoring"], "goal_authoring")),
            _task_authoring=deepcopy(_object(data["task_authoring"], "task_authoring")),
        )

    def goal_authoring(self) -> Mapping[str, Any]:
        return deepcopy(self._goal_authoring)

    def task_authoring(self) -> Mapping[str, Any]:
        return deepcopy(self._task_authoring)


@dataclass(frozen=True)
class AOSCoreBundle:
    """Smallest cross-domain executable handoff supported by AOS Core v0.1."""

    pack_id: str
    pack_version: str
    domain_ref: str
    goal: GoalSpec
    task: TaskSpec
    goal_source_digest: str
    task_source_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "contract_version": CORE_CONTRACT_VERSION,
            "domain_pack": {"pack_id": self.pack_id, "pack_version": self.pack_version},
            "domain_ref": self.domain_ref,
            "goal_spec": self.goal.to_dict(),
            "task_spec": self.task.to_dict(),
            "source_digests": {
                "goal_authoring": self.goal_source_digest,
                "task_authoring": self.task_source_digest,
            },
        }

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> "AOSCoreBundle":
        _exact_fields(data, _BUNDLE_FIELDS, "AOS Core bundle")
        if data["contract_version"] != CORE_CONTRACT_VERSION:
            raise ContractError("unsupported AOS Core contract_version")
        identity = _object(data["domain_pack"], "domain_pack")
        _exact_fields(identity, frozenset({"pack_id", "pack_version"}), "domain_pack")
        digests = _object(data["source_digests"], "source_digests")
        _exact_fields(
            digests,
            frozenset({"goal_authoring", "task_authoring"}),
            "source_digests",
        )
        pack_id = _pack_id(identity["pack_id"])
        domain_ref = _text(data["domain_ref"], "domain_ref")
        if not domain_ref.startswith(f"domain://{pack_id}/"):
            raise ContractError("domain_ref must be an opaque URI owned by pack_id")
        goal = GoalSpec.from_dict(_object(data["goal_spec"], "goal_spec"))
        task = TaskSpec.from_dict(_object(data["task_spec"], "task_spec"))
        validate_task_within_goal(goal, task)
        return cls(
            pack_id=pack_id,
            pack_version=_text(identity["pack_version"], "pack_version"),
            domain_ref=domain_ref,
            goal=goal,
            task=task,
            goal_source_digest=_digest(digests["goal_authoring"], "goal_source_digest"),
            task_source_digest=_digest(digests["task_authoring"], "task_source_digest"),
        )


@dataclass(frozen=True)
class DomainPackConformanceReport:
    pack_id: str
    domain: str
    goal_id: str
    task_id: str
    bundle_digest: str
    checks: Mapping[str, str]
    status: str = "passed"
    evidence_state: str = "runtime_verification"
    non_claims: tuple[str, ...] = (
        "provider_smoke",
        "human_acceptance",
        "business_validation",
        "active_rule_promotion",
        "public_standard_status",
    )

    def to_wire(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "domain": self.domain,
            "goal_id": self.goal_id,
            "task_id": self.task_id,
            "status": self.status,
            "bundle_digest": self.bundle_digest,
            "checks": dict(self.checks),
            "evidence_state": self.evidence_state,
            "non_claims": list(self.non_claims),
        }


def compile_domain_pack(pack: DomainPack) -> AOSCoreBundle:
    pack_id = _pack_id(pack.pack_id)
    domain_ref = _text(pack.domain_ref, "domain_ref")
    if not domain_ref.startswith(f"domain://{pack_id}/"):
        raise ContractError("domain_ref must be an opaque URI owned by pack_id")
    goal, goal_result = compile_goal(pack.goal_authoring())
    task, task_result = compile_task(pack.task_authoring(), goal=goal)
    adapter_prefix = f"{pack_id}."
    if any(
        not step["adapter"].startswith(adapter_prefix) for step in task.workflow_steps
    ):
        raise ContractError("workflow adapter ids must be namespaced by pack_id")
    return AOSCoreBundle(
        pack_id=pack_id,
        pack_version=_text(pack.pack_version, "pack_version"),
        domain_ref=domain_ref,
        goal=goal,
        task=task,
        goal_source_digest=goal_result.source_digest,
        task_source_digest=task_result.source_digest,
    )


def run_domain_pack_conformance(pack: DomainPack) -> DomainPackConformanceReport:
    first = compile_domain_pack(pack)
    replay = compile_domain_pack(pack)
    first_wire = first.to_wire()
    replay_wire = replay.to_wire()
    if first_wire != replay_wire:
        raise IntegrityError("domain pack compilation is not deterministic")
    roundtrip = AOSCoreBundle.from_wire(first_wire)
    if roundtrip.to_wire() != first_wire:
        raise IntegrityError("AOS Core bundle roundtrip changed the object")
    return DomainPackConformanceReport(
        pack_id=first.pack_id,
        domain=_text(pack.domain, "domain"),
        goal_id=first.goal.goal_id,
        task_id=first.task.task_id,
        bundle_digest=content_hash(first_wire),
        checks={
            "strict_goal_compile": "passed",
            "strict_task_compile": "passed",
            "authority_subset": "passed",
            "adapter_namespace": "passed",
            "opaque_domain_reference": "passed",
            "deterministic_recompile": "passed",
            "strict_bundle_roundtrip": "passed",
        },
    )


def run_cross_domain_conformance(packs: list[DomainPack]) -> dict[str, Any]:
    if len(packs) < 2:
        raise ContractError(
            "cross-domain conformance requires at least two Domain Packs"
        )
    reports = [run_domain_pack_conformance(pack) for pack in packs]
    pack_ids = [report.pack_id for report in reports]
    domains = [report.domain for report in reports]
    goal_ids = [report.goal_id for report in reports]
    task_ids = [report.task_id for report in reports]
    if any(
        len(values) != len(set(values))
        for values in (pack_ids, domains, goal_ids, task_ids)
    ):
        raise ContractError(
            "cross-domain conformance requires unique packs, domains, and core ids"
        )
    return {
        "contract_version": CORE_CONTRACT_VERSION,
        "status": "passed",
        "checks": {
            "unique_domain_packs": "passed",
            "unique_core_ids": "passed",
            "shared_core_contract": "passed",
            "domain_payload_outside_core": "passed",
        },
        "packs": [report.to_wire() for report in reports],
        "evidence_state": "runtime_verification",
        "non_claims": [
            "provider_smoke",
            "human_acceptance",
            "business_validation",
            "active_rule_promotion",
            "public_standard_status",
        ],
    }
