"""Strict Project -> Program -> Goal -> Task authority contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Mapping

from .errors import ContractError
from .scope import normalize_scope, scope_allowed, scopes_overlap
from .types import Capability, GoalSpec, RuntimeSurfaceSpec, TaskSpec, content_hash


def _strict_keys(
    data: Mapping[str, Any], required: set[str], allowed: set[str], label: str
) -> None:
    missing = required - set(data)
    unknown = set(data) - allowed
    if missing:
        raise ContractError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unsupported fields: {sorted(unknown)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ContractError(f"{label} must be a non-empty trimmed string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"{label} must be a positive integer")
    return value


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be a list")
    result = tuple(_text(item, label) for item in value)
    if len(result) != len(set(result)):
        raise ContractError(f"{label} must not contain duplicates")
    return result


class ProgramState(StrEnum):
    COMPILED = "compiled"
    ACTIVE = "active"
    DELIVERED = "delivered"
    CANCELED = "canceled"
    RETIRED = "retired"

    @property
    def terminal(self) -> bool:
        return self in {self.DELIVERED, self.CANCELED, self.RETIRED}


@dataclass(frozen=True)
class AuthorityRef:
    kind: str
    object_id: str
    version: int
    digest: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuthorityRef":
        allowed = {"kind", "object_id", "version", "digest"}
        _strict_keys(data, allowed, allowed, "authority_ref")
        kind = _text(data["kind"], "authority_ref.kind")
        if kind not in {"project", "program", "goal"}:
            raise ContractError(f"unsupported authority_ref.kind: {kind}")
        digest = _text(data["digest"], "authority_ref.digest")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ContractError("authority_ref.digest must be lowercase SHA-256 hex")
        return cls(
            kind=kind,
            object_id=_text(data["object_id"], "authority_ref.object_id"),
            version=_positive_int(data["version"], "authority_ref.version"),
            digest=digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthorityBounds:
    capabilities: tuple[Capability, ...]
    read_scope: tuple[str, ...]
    write_scope: tuple[str, ...]
    forbidden_scope: tuple[str, ...]
    required_runtime_surfaces: tuple[RuntimeSurfaceSpec, ...]
    provider_budget_minor_units: int
    provider_call_limit: int
    budget_currency: str
    evaluator_required: bool
    required_decision_gates: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuthorityBounds":
        fields = {
            "capabilities",
            "read_scope",
            "write_scope",
            "forbidden_scope",
            "required_runtime_surfaces",
            "provider_budget_minor_units",
            "provider_call_limit",
            "budget_currency",
            "evaluator_required",
            "required_decision_gates",
        }
        _strict_keys(data, fields, fields, "authority_bounds")
        raw_capabilities = data["capabilities"]
        if not isinstance(raw_capabilities, list):
            raise ContractError("authority_bounds.capabilities must be a list")
        try:
            capabilities = tuple(Capability(item) for item in raw_capabilities)
        except ValueError as exc:
            raise ContractError(str(exc)) from exc
        if len(capabilities) != len(set(capabilities)):
            raise ContractError(
                "authority_bounds.capabilities must not contain duplicates"
            )
        raw_surfaces = data["required_runtime_surfaces"]
        if not isinstance(raw_surfaces, list) or not all(
            isinstance(item, Mapping) for item in raw_surfaces
        ):
            raise ContractError("required_runtime_surfaces must be a list of objects")
        surfaces = tuple(RuntimeSurfaceSpec.from_dict(item) for item in raw_surfaces)
        surface_keys = [item.surface_key for item in surfaces]
        if len(surface_keys) != len(set(surface_keys)):
            raise ContractError("required_runtime_surfaces has duplicate surface_key")
        evaluator_required = data["evaluator_required"]
        if not isinstance(evaluator_required, bool):
            raise ContractError("authority_bounds.evaluator_required must be a boolean")
        currency = _text(data["budget_currency"], "budget_currency").upper()
        if len(currency) != 3 or not currency.isascii() or not currency.isalpha():
            raise ContractError("budget_currency must be three ASCII letters")
        result = cls(
            capabilities=capabilities,
            read_scope=_strings(data["read_scope"], "read_scope"),
            write_scope=_strings(data["write_scope"], "write_scope"),
            forbidden_scope=_strings(data["forbidden_scope"], "forbidden_scope"),
            required_runtime_surfaces=surfaces,
            provider_budget_minor_units=_non_negative_int(
                data["provider_budget_minor_units"], "provider_budget_minor_units"
            ),
            provider_call_limit=_non_negative_int(
                data["provider_call_limit"], "provider_call_limit"
            ),
            budget_currency=currency,
            evaluator_required=evaluator_required,
            required_decision_gates=_strings(
                data["required_decision_gates"], "required_decision_gates"
            ),
        )
        validate_bounds(result, label="authority")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [item.value for item in self.capabilities],
            "read_scope": list(self.read_scope),
            "write_scope": list(self.write_scope),
            "forbidden_scope": list(self.forbidden_scope),
            "required_runtime_surfaces": [
                item.to_dict() for item in self.required_runtime_surfaces
            ],
            "provider_budget_minor_units": self.provider_budget_minor_units,
            "provider_call_limit": self.provider_call_limit,
            "budget_currency": self.budget_currency,
            "evaluator_required": self.evaluator_required,
            "required_decision_gates": list(self.required_decision_gates),
        }


def validate_bounds(bounds: AuthorityBounds, *, label: str) -> None:
    currency_valid = (
        len(bounds.budget_currency) == 3
        and bounds.budget_currency.isascii()
        and bounds.budget_currency.isalpha()
        and bounds.budget_currency == bounds.budget_currency.upper()
    )
    if not currency_valid:
        raise ContractError(
            f"{label} budget currency must be three uppercase ASCII letters"
        )
    _non_negative_int(
        bounds.provider_budget_minor_units, f"{label} provider_budget_minor_units"
    )
    _non_negative_int(bounds.provider_call_limit, f"{label} provider_call_limit")
    for value in (*bounds.read_scope, *bounds.write_scope, *bounds.forbidden_scope):
        normalize_scope(value)
    conflicts = [
        (scope, denied)
        for scope in (*bounds.read_scope, *bounds.write_scope)
        for denied in bounds.forbidden_scope
        if scopes_overlap(scope, denied)
    ]
    if conflicts:
        raise ContractError(f"{label} scope intersects forbidden scope: {conflicts}")
    if (
        Capability.PROVIDER_COST in bounds.capabilities
        and bounds.provider_call_limit < 1
    ):
        raise ContractError(f"{label} provider_cost requires a positive call limit")


def validate_child_bounds(
    parent: AuthorityBounds, child: AuthorityBounds, *, label: str
) -> None:
    validate_bounds(parent, label=f"{label} parent")
    validate_bounds(child, label=label)
    extra_capabilities = set(child.capabilities) - set(parent.capabilities)
    if extra_capabilities:
        names = sorted(item.value for item in extra_capabilities)
        raise ContractError(f"{label} capabilities exceed parent authority: {names}")
    for scope_label, allowed, requested in (
        ("read_scope", parent.read_scope, child.read_scope),
        ("write_scope", parent.write_scope, child.write_scope),
    ):
        uncovered = [item for item in requested if not scope_allowed(allowed, item)]
        if uncovered:
            raise ContractError(
                f"{label} {scope_label} exceeds parent authority: {uncovered}"
            )
    inherited_conflicts = [
        (scope, denied)
        for scope in (*child.read_scope, *child.write_scope)
        for denied in parent.forbidden_scope
        if scopes_overlap(scope, denied)
    ]
    if inherited_conflicts:
        raise ContractError(
            f"{label} scope intersects inherited forbidden scope: {inherited_conflicts}"
        )
    parent_surfaces = {
        item.surface_key: item for item in parent.required_runtime_surfaces
    }
    child_surfaces = {
        item.surface_key: item for item in child.required_runtime_surfaces
    }
    extra_surfaces = [
        item.surface_key
        for item in child.required_runtime_surfaces
        if parent_surfaces.get(item.surface_key) != item
    ]
    if extra_surfaces:
        raise ContractError(
            f"{label} runtime surfaces exceed parent authority: {sorted(extra_surfaces)}"
        )
    missing_surfaces = [
        key
        for key, value in parent_surfaces.items()
        if child_surfaces.get(key) != value
    ]
    if missing_surfaces:
        raise ContractError(
            f"{label} cannot drop required runtime surfaces: {sorted(missing_surfaces)}"
        )
    if child.budget_currency != parent.budget_currency:
        raise ContractError(f"{label} budget currency differs from parent")
    if child.provider_budget_minor_units > parent.provider_budget_minor_units:
        raise ContractError(f"{label} provider budget exceeds parent authority")
    if child.provider_call_limit > parent.provider_call_limit:
        raise ContractError(f"{label} provider call limit exceeds parent authority")
    if parent.evaluator_required and not child.evaluator_required:
        raise ContractError(f"{label} cannot remove required evaluator policy")
    missing_gates = set(parent.required_decision_gates) - set(
        child.required_decision_gates
    )
    if missing_gates:
        raise ContractError(
            f"{label} cannot remove parent decision gates: {sorted(missing_gates)}"
        )


@dataclass(frozen=True)
class ProjectSpec:
    project_id: str
    version: int
    target_outcome: str
    authority: AuthorityBounds
    schema_version: str = "companyos.project-spec.v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProjectSpec":
        fields = {
            "schema_version",
            "project_id",
            "version",
            "target_outcome",
            "authority",
        }
        _strict_keys(data, fields, fields, "project_spec")
        if data["schema_version"] != "companyos.project-spec.v1":
            raise ContractError("unsupported project_spec schema_version")
        if not isinstance(data["authority"], Mapping):
            raise ContractError("project_spec.authority must be an object")
        return cls(
            project_id=_text(data["project_id"], "project_id"),
            version=_positive_int(data["version"], "project version"),
            target_outcome=_text(data["target_outcome"], "target_outcome"),
            authority=AuthorityBounds.from_dict(data["authority"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "version": self.version,
            "target_outcome": self.target_outcome,
            "authority": self.authority.to_dict(),
        }

    def reference(self) -> AuthorityRef:
        return AuthorityRef(
            "project", self.project_id, self.version, content_hash(self.to_dict())
        )


@dataclass(frozen=True)
class ProgramSpec:
    program_id: str
    version: int
    project_ref: AuthorityRef
    objective: str
    state: ProgramState
    dependency_refs: tuple[AuthorityRef, ...]
    wave: int
    authority: AuthorityBounds
    schema_version: str = "companyos.program-spec.v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProgramSpec":
        fields = {
            "schema_version",
            "program_id",
            "version",
            "project_ref",
            "objective",
            "state",
            "dependency_refs",
            "wave",
            "authority",
        }
        _strict_keys(data, fields, fields, "program_spec")
        if data["schema_version"] != "companyos.program-spec.v1":
            raise ContractError("unsupported program_spec schema_version")
        if not isinstance(data["project_ref"], Mapping):
            raise ContractError("program_spec.project_ref must be an object")
        if not isinstance(data["dependency_refs"], list) or not all(
            isinstance(item, Mapping) for item in data["dependency_refs"]
        ):
            raise ContractError(
                "program_spec.dependency_refs must be a list of objects"
            )
        if not isinstance(data["authority"], Mapping):
            raise ContractError("program_spec.authority must be an object")
        project_ref = AuthorityRef.from_dict(data["project_ref"])
        if project_ref.kind != "project":
            raise ContractError("program_spec.project_ref must reference a project")
        dependencies = tuple(
            AuthorityRef.from_dict(item) for item in data["dependency_refs"]
        )
        if any(item.kind != "program" for item in dependencies):
            raise ContractError("program dependencies must reference programs")
        if len(dependencies) != len(set(dependencies)):
            raise ContractError("program dependencies must not contain duplicates")
        try:
            state = ProgramState(data["state"])
        except ValueError as exc:
            raise ContractError(str(exc)) from exc
        wave = _non_negative_int(data["wave"], "program wave")
        program_id = _text(data["program_id"], "program_id")
        if any(item.object_id == program_id for item in dependencies):
            raise ContractError("program cannot depend on itself")
        return cls(
            program_id=program_id,
            version=_positive_int(data["version"], "program version"),
            project_ref=project_ref,
            objective=_text(data["objective"], "program objective"),
            state=state,
            dependency_refs=dependencies,
            wave=wave,
            authority=AuthorityBounds.from_dict(data["authority"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "program_id": self.program_id,
            "version": self.version,
            "project_ref": self.project_ref.to_dict(),
            "objective": self.objective,
            "state": self.state.value,
            "dependency_refs": [item.to_dict() for item in self.dependency_refs],
            "wave": self.wave,
            "authority": self.authority.to_dict(),
        }

    def reference(self) -> AuthorityRef:
        return AuthorityRef(
            "program", self.program_id, self.version, content_hash(self.to_dict())
        )


@dataclass(frozen=True)
class CompiledGoalAuthority:
    version: int
    project_ref: AuthorityRef
    program_ref: AuthorityRef
    required_decision_gates: tuple[str, ...]
    goal_spec: GoalSpec
    schema_version: str = "companyos.compiled-goal-authority.v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompiledGoalAuthority":
        fields = {
            "schema_version",
            "version",
            "project_ref",
            "program_ref",
            "required_decision_gates",
            "goal_spec",
        }
        _strict_keys(data, fields, fields, "compiled_goal_authority")
        if data["schema_version"] != "companyos.compiled-goal-authority.v1":
            raise ContractError("unsupported compiled_goal_authority schema_version")
        if not all(
            isinstance(data[name], Mapping)
            for name in ("project_ref", "program_ref", "goal_spec")
        ):
            raise ContractError(
                "compiled_goal_authority refs and goal_spec must be objects"
            )
        project_ref = AuthorityRef.from_dict(data["project_ref"])
        program_ref = AuthorityRef.from_dict(data["program_ref"])
        if project_ref.kind != "project" or program_ref.kind != "program":
            raise ContractError("compiled_goal_authority has invalid parent ref kinds")
        return cls(
            version=_positive_int(data["version"], "goal authority version"),
            project_ref=project_ref,
            program_ref=program_ref,
            required_decision_gates=_strings(
                data["required_decision_gates"], "required_decision_gates"
            ),
            goal_spec=GoalSpec.from_dict(data["goal_spec"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "project_ref": self.project_ref.to_dict(),
            "program_ref": self.program_ref.to_dict(),
            "required_decision_gates": list(self.required_decision_gates),
            "goal_spec": self.goal_spec.to_dict(),
        }

    def reference(self) -> AuthorityRef:
        return AuthorityRef(
            "goal", self.goal_spec.goal_id, self.version, content_hash(self.to_dict())
        )


@dataclass(frozen=True)
class DecisionGateContract:
    gate_id: str
    capability: Capability
    action: str
    resource: str
    request_digest: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DecisionGateContract":
        fields = {"gate_id", "capability", "action", "resource", "request_digest"}
        _strict_keys(data, fields, fields, "decision_gate_contract")
        try:
            capability = Capability(
                _text(data["capability"], "decision gate capability")
            )
        except ValueError as exc:
            raise ContractError(str(exc)) from exc
        resource = _text(data["resource"], "decision gate resource")
        if "://" not in resource or "*" in resource:
            raise ContractError(
                "decision gate resource must be an exact typed resource"
            )
        request_digest = _text(data["request_digest"], "decision gate request_digest")
        if len(request_digest) != 64 or any(
            character not in "0123456789abcdef" for character in request_digest
        ):
            raise ContractError(
                "decision gate request_digest must be lowercase SHA-256 hex"
            )
        return cls(
            gate_id=_text(data["gate_id"], "decision gate id"),
            capability=capability,
            action=_text(data["action"], "decision gate action"),
            resource=resource,
            request_digest=request_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "capability": self.capability.value,
            "action": self.action,
            "resource": self.resource,
            "request_digest": self.request_digest,
        }


_DECISION_GATE_DEFINITIONS = {
    "provider": (Capability.PROVIDER_COST, "generate", "provider://"),
    "merge": (Capability.REPO_REMOTE, "merge", "repo://"),
    "release": (Capability.PUBLIC_RELEASE, "release", "release://"),
}


def _canonical_decision_gate_contracts(
    task: TaskSpec, gates: tuple[str, ...]
) -> tuple[DecisionGateContract, ...]:
    contracts: list[DecisionGateContract] = []
    for gate in gates:
        definition = _DECISION_GATE_DEFINITIONS.get(gate)
        if definition is None:
            raise ContractError(
                f"Task decision gate has no explicit decision authority: {gate}"
            )
        capability, action, scheme = definition
        resources = tuple(
            scope
            for scope in task.write_scope
            if scope.casefold().startswith(scheme) and "*" not in scope
        )
        if len(resources) != 1:
            raise ContractError(
                f"Task decision gate {gate} requires exactly one exact {scheme} write_scope"
            )
        resource = resources[0]
        contracts.append(
            DecisionGateContract(
                gate_id=gate,
                capability=capability,
                action=action,
                resource=resource,
                request_digest=content_hash(
                    {
                        "gate_id": gate,
                        "capability": capability.value,
                        "action": action,
                        "resource": resource,
                    }
                ),
            )
        )
    return tuple(contracts)


@dataclass(frozen=True)
class CompiledTaskAuthority:
    version: int
    project_ref: AuthorityRef
    program_ref: AuthorityRef
    goal_ref: AuthorityRef
    required_decision_gates: tuple[str, ...]
    decision_gate_contracts: tuple[DecisionGateContract, ...]
    provider_budget_minor_units: int
    provider_call_limit: int
    budget_currency: str
    task_spec: TaskSpec
    schema_version: str = "companyos.compiled-task-authority.v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompiledTaskAuthority":
        fields = {
            "schema_version",
            "version",
            "project_ref",
            "program_ref",
            "goal_ref",
            "required_decision_gates",
            "provider_budget_minor_units",
            "decision_gate_contracts",
            "provider_call_limit",
            "budget_currency",
            "task_spec",
        }
        _strict_keys(data, fields, fields, "compiled_task_authority")
        if data["schema_version"] != "companyos.compiled-task-authority.v1":
            raise ContractError("unsupported compiled_task_authority schema_version")
        if not all(
            isinstance(data[name], Mapping)
            for name in ("project_ref", "program_ref", "goal_ref", "task_spec")
        ):
            raise ContractError(
                "compiled_task_authority refs and task_spec must be objects"
            )
        project_ref = AuthorityRef.from_dict(data["project_ref"])
        program_ref = AuthorityRef.from_dict(data["program_ref"])
        goal_ref = AuthorityRef.from_dict(data["goal_ref"])
        if (project_ref.kind, program_ref.kind, goal_ref.kind) != (
            "project",
            "program",
            "goal",
        ):
            raise ContractError("compiled_task_authority has invalid parent ref kinds")
        currency = _text(data["budget_currency"], "task budget_currency").upper()
        required_decision_gates = _strings(
            data["required_decision_gates"], "required_decision_gates"
        )
        task_spec = TaskSpec.from_dict(data["task_spec"])
        result = cls(
            version=_positive_int(data["version"], "task authority version"),
            project_ref=project_ref,
            program_ref=program_ref,
            goal_ref=goal_ref,
            required_decision_gates=required_decision_gates,
            decision_gate_contracts=tuple(
                DecisionGateContract.from_dict(item)
                for item in data["decision_gate_contracts"]
            )
            if isinstance(data["decision_gate_contracts"], list)
            else (),
            provider_budget_minor_units=_non_negative_int(
                data["provider_budget_minor_units"], "task provider budget"
            ),
            provider_call_limit=_non_negative_int(
                data["provider_call_limit"], "task provider call limit"
            ),
            budget_currency=currency,
            task_spec=task_spec,
        )
        if len(currency) != 3 or not currency.isascii() or not currency.isalpha():
            raise ContractError("task budget_currency must be three ASCII letters")
        if not isinstance(data["decision_gate_contracts"], list):
            raise ContractError("decision_gate_contracts must be a list")
        gate_ids = tuple(item.gate_id for item in result.decision_gate_contracts)
        if gate_ids != result.required_decision_gates or len(gate_ids) != len(
            set(gate_ids)
        ):
            raise ContractError(
                "decision_gate_contracts must exactly match required_decision_gates order"
            )
        if result.decision_gate_contracts != _canonical_decision_gate_contracts(
            task_spec, required_decision_gates
        ):
            raise ContractError(
                "decision_gate_contracts do not match canonical Task gate authority"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "project_ref": self.project_ref.to_dict(),
            "program_ref": self.program_ref.to_dict(),
            "goal_ref": self.goal_ref.to_dict(),
            "required_decision_gates": list(self.required_decision_gates),
            "decision_gate_contracts": [
                item.to_dict() for item in self.decision_gate_contracts
            ],
            "provider_budget_minor_units": self.provider_budget_minor_units,
            "provider_call_limit": self.provider_call_limit,
            "budget_currency": self.budget_currency,
            "task_spec": self.task_spec.to_dict(),
        }
