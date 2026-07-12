"""Compilation functions for the versioned Project/Program authority spine."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from .authority import (
    AuthorityBounds,
    CompiledGoalAuthority,
    CompiledTaskAuthority,
    ProgramSpec,
    ProjectSpec,
    _non_negative_int,
    _positive_int,
    validate_child_bounds,
)
from .compiler import CompilationResult, compile_goal, compile_task
from .errors import ContractError
from .types import Capability, GoalSpec


_DECISION_GATE_CAPABILITIES = {
    "provider": Capability.PROVIDER_COST,
    "merge": Capability.REPO_REMOTE,
    "release": Capability.PUBLIC_RELEASE,
}


class CurrentProgramStateProvider(Protocol):
    """Trusted application boundary for active/terminal Program versions."""

    def current_program(
        self, *, project_ref: object, program_id: str
    ) -> ProgramSpec | None: ...


def _goal_bounds(goal: GoalSpec, decision_gates: tuple[str, ...]) -> AuthorityBounds:
    return AuthorityBounds(
        capabilities=goal.allowed_capabilities,
        read_scope=goal.read_scope,
        write_scope=goal.write_scope,
        forbidden_scope=goal.forbidden_scope,
        required_runtime_surfaces=goal.required_runtime_surfaces,
        provider_budget_minor_units=goal.provider_budget_minor_units,
        provider_call_limit=goal.provider_call_limit,
        budget_currency=goal.budget_currency,
        evaluator_required=goal.evaluator_required,
        required_decision_gates=decision_gates,
    )


def compile_project(data: Mapping[str, Any]) -> ProjectSpec:
    return ProjectSpec.from_dict(data)


def compile_program(
    data: Mapping[str, Any],
    *,
    project: ProjectSpec,
    program_graph: Sequence[ProgramSpec] | None = None,
    current_state_provider: CurrentProgramStateProvider | None = None,
) -> ProgramSpec:
    canonical_project = ProjectSpec.from_dict(project.to_dict())
    program = ProgramSpec.from_dict(data)
    if program.project_ref != canonical_project.reference():
        raise ContractError(
            "program project_ref does not match exact ProjectSpec version/digest"
        )
    validate_child_bounds(
        canonical_project.authority, program.authority, label="program"
    )
    if program.state is not program.state.COMPILED:
        if current_state_provider is None:
            raise ContractError(
                "non-compiled Program requires a trusted current-state provider"
            )
        current = current_state_provider.current_program(
            project_ref=canonical_project.reference(), program_id=program.program_id
        )
        if current is None or ProgramSpec.from_dict(current.to_dict()).reference() != program.reference():
            raise ContractError("Program is not the provider-verified current version")
    if program.dependency_refs:
        if program_graph is None:
            raise ContractError("Program dependencies require a complete graph proof")
        canonical_graph = tuple(ProgramSpec.from_dict(item.to_dict()) for item in program_graph)
        if program.reference() not in {item.reference() for item in canonical_graph}:
            raise ContractError("Program graph proof does not contain the exact Program version")
        validate_program_graph(canonical_project, canonical_graph)
    return program


def validate_goal_authority(
    authority: CompiledGoalAuthority,
    *,
    project: ProjectSpec,
    program: ProgramSpec,
    program_graph: Sequence[ProgramSpec] | None = None,
    current_state_provider: CurrentProgramStateProvider | None = None,
) -> CompiledGoalAuthority:
    canonical_project = ProjectSpec.from_dict(project.to_dict())
    canonical_program = compile_program(
        program.to_dict(),
        project=canonical_project,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    )
    canonical = CompiledGoalAuthority.from_dict(authority.to_dict())
    if canonical_program.state.terminal:
        raise ContractError("terminal Program cannot accept a new Goal")
    if canonical.project_ref != canonical_project.reference():
        raise ContractError("Goal cannot bypass Project authority")
    if canonical.program_ref != canonical_program.reference():
        raise ContractError("Goal cannot bypass Program authority")
    if canonical.required_decision_gates != canonical_program.authority.required_decision_gates:
        raise ContractError("Goal decision gates do not match Program authority")
    validate_child_bounds(
        canonical_program.authority,
        _goal_bounds(
            canonical.goal_spec,
            canonical_program.authority.required_decision_gates,
        ),
        label="goal",
    )
    return canonical


def validate_program_graph(project: ProjectSpec, programs: Sequence[ProgramSpec]) -> None:
    by_id = {item.program_id: item for item in programs}
    if len(by_id) != len(programs):
        raise ContractError("program graph contains duplicate program_id values")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(program_id: str) -> None:
        if program_id in visiting:
            raise ContractError("program dependency cycle detected")
        if program_id in visited:
            return
        visiting.add(program_id)
        for dependency in by_id[program_id].dependency_refs:
            if dependency.object_id in by_id:
                visit(dependency.object_id)
        visiting.remove(program_id)
        visited.add(program_id)

    for program_id in by_id:
        visit(program_id)
    for program in programs:
        if program.project_ref != project.reference():
            raise ContractError(f"program belongs to another project: {program.program_id}")
        validate_child_bounds(project.authority, program.authority, label="program")
        for dependency in program.dependency_refs:
            target = by_id.get(dependency.object_id)
            if target is None or dependency != target.reference():
                raise ContractError(
                    f"program dependency ref is missing or stale: {dependency.object_id}"
                )
            if target.wave >= program.wave:
                raise ContractError("program dependencies must be in an earlier wave")


def compile_goal_authority(
    authoring: Mapping[str, Any],
    *,
    project: ProjectSpec,
    program: ProgramSpec,
    version: int = 1,
    program_graph: Sequence[ProgramSpec] | None = None,
    current_state_provider: CurrentProgramStateProvider | None = None,
) -> tuple[CompiledGoalAuthority, CompilationResult]:
    goal, result = compile_goal(authoring)
    candidate = CompiledGoalAuthority(
        version=_positive_int(version, "goal authority version"),
        project_ref=ProjectSpec.from_dict(project.to_dict()).reference(),
        program_ref=ProgramSpec.from_dict(program.to_dict()).reference(),
        required_decision_gates=ProgramSpec.from_dict(
            program.to_dict()
        ).authority.required_decision_gates,
        goal_spec=goal,
    )
    return validate_goal_authority(
        candidate,
        project=project,
        program=program,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    ), result


def validate_task_authority(
    authority: CompiledTaskAuthority,
    *,
    project: ProjectSpec,
    program: ProgramSpec,
    goal: CompiledGoalAuthority,
    program_graph: Sequence[ProgramSpec] | None = None,
    current_state_provider: CurrentProgramStateProvider | None = None,
) -> CompiledTaskAuthority:
    canonical_project = ProjectSpec.from_dict(project.to_dict())
    canonical_program = compile_program(
        program.to_dict(),
        project=canonical_project,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    )
    canonical_goal = validate_goal_authority(
        goal,
        project=canonical_project,
        program=canonical_program,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    )
    canonical = CompiledTaskAuthority.from_dict(authority.to_dict())
    if canonical_program.state.terminal:
        raise ContractError("terminal Program cannot accept a new Task")
    if canonical.project_ref != canonical_project.reference():
        raise ContractError("Task cannot cross project authority")
    if canonical.program_ref != canonical_program.reference():
        raise ContractError("Task cannot bypass Program authority")
    if canonical.goal_ref != canonical_goal.reference():
        raise ContractError("Task cannot bypass Goal authority")
    if canonical.required_decision_gates != canonical_goal.required_decision_gates:
        raise ContractError("Task decision gates do not match compiled Goal authority")
    for gate in canonical.required_decision_gates:
        capability = _DECISION_GATE_CAPABILITIES.get(gate)
        if capability is None:
            raise ContractError(
                f"Task decision gate has no explicit decision authority: {gate}"
            )
        if capability not in canonical.task_spec.capabilities:
            raise ContractError(
                f"Task decision gate {gate} requires capability {capability.value}"
            )
    if "provider" in canonical.required_decision_gates and (
        canonical.provider_budget_minor_units < 1
        or canonical.provider_call_limit < 1
    ):
        raise ContractError(
            "Task provider decision gate requires a positive Task budget and call limit"
        )
    if canonical.task_spec.goal_id != canonical_goal.goal_spec.goal_id:
        raise ContractError("Task goal_id does not match compiled Goal authority")
    task_bounds = AuthorityBounds(
        capabilities=canonical.task_spec.capabilities,
        read_scope=canonical.task_spec.read_scope,
        write_scope=canonical.task_spec.write_scope,
        forbidden_scope=canonical.task_spec.forbidden_scope,
        required_runtime_surfaces=canonical.task_spec.required_runtime_surfaces,
        provider_budget_minor_units=canonical.provider_budget_minor_units,
        provider_call_limit=canonical.provider_call_limit,
        budget_currency=canonical.budget_currency,
        evaluator_required=canonical.task_spec.evaluator_required,
        required_decision_gates=canonical_program.authority.required_decision_gates,
    )
    validate_child_bounds(
        _goal_bounds(
            canonical_goal.goal_spec,
            canonical_program.authority.required_decision_gates,
        ),
        task_bounds,
        label="task",
    )
    return canonical


def compile_task_authority(
    authoring: Mapping[str, Any],
    *,
    project: ProjectSpec,
    program: ProgramSpec,
    goal: CompiledGoalAuthority,
    provider_budget_minor_units: int = 0,
    provider_call_limit: int = 0,
    budget_currency: str | None = None,
    version: int = 1,
    program_graph: Sequence[ProgramSpec] | None = None,
    current_state_provider: CurrentProgramStateProvider | None = None,
) -> tuple[CompiledTaskAuthority, CompilationResult]:
    canonical_goal = validate_goal_authority(
        goal,
        project=project,
        program=program,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    )
    task, result = compile_task(authoring, goal=canonical_goal.goal_spec)
    currency = (budget_currency or canonical_goal.goal_spec.budget_currency).upper()
    task_bounds = AuthorityBounds(
        capabilities=task.capabilities,
        read_scope=task.read_scope,
        write_scope=task.write_scope,
        forbidden_scope=task.forbidden_scope,
        required_runtime_surfaces=task.required_runtime_surfaces,
        provider_budget_minor_units=_non_negative_int(
            provider_budget_minor_units, "task provider budget"
        ),
        provider_call_limit=_non_negative_int(
            provider_call_limit, "task provider call limit"
        ),
        budget_currency=currency,
        evaluator_required=task.evaluator_required,
        required_decision_gates=program.authority.required_decision_gates,
    )
    candidate = CompiledTaskAuthority(
            version=_positive_int(version, "task authority version"),
            project_ref=ProjectSpec.from_dict(project.to_dict()).reference(),
            program_ref=ProgramSpec.from_dict(program.to_dict()).reference(),
            goal_ref=canonical_goal.reference(),
            required_decision_gates=canonical_goal.required_decision_gates,
            provider_budget_minor_units=task_bounds.provider_budget_minor_units,
            provider_call_limit=task_bounds.provider_call_limit,
            budget_currency=task_bounds.budget_currency,
            task_spec=task,
    )
    return validate_task_authority(
        candidate,
        project=project,
        program=program,
        goal=canonical_goal,
        program_graph=program_graph,
        current_state_provider=current_state_provider,
    ), result
