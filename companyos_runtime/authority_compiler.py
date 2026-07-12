"""Compilation functions for the versioned Project/Program authority spine."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

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
from .types import GoalSpec


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


def compile_program(data: Mapping[str, Any], *, project: ProjectSpec) -> ProgramSpec:
    program = ProgramSpec.from_dict(data)
    if program.project_ref != project.reference():
        raise ContractError(
            "program project_ref does not match exact ProjectSpec version/digest"
        )
    validate_child_bounds(project.authority, program.authority, label="program")
    return program


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
) -> tuple[CompiledGoalAuthority, CompilationResult]:
    if program.state.terminal:
        raise ContractError("terminal Program cannot accept a new Goal")
    if program.project_ref != project.reference():
        raise ContractError("Goal cannot bypass Program or cross project authority")
    goal, result = compile_goal(authoring)
    validate_child_bounds(
        program.authority,
        _goal_bounds(goal, program.authority.required_decision_gates),
        label="goal",
    )
    return (
        CompiledGoalAuthority(
            version=_positive_int(version, "goal authority version"),
            project_ref=project.reference(),
            program_ref=program.reference(),
            goal_spec=goal,
        ),
        result,
    )


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
) -> tuple[CompiledTaskAuthority, CompilationResult]:
    if program.state.terminal:
        raise ContractError("terminal Program cannot accept a new Task")
    if program.project_ref != project.reference() or goal.project_ref != project.reference():
        raise ContractError("Task cannot cross project authority")
    if goal.program_ref != program.reference():
        raise ContractError("Task cannot bypass Program or Goal authority")
    task, result = compile_task(authoring, goal=goal.goal_spec)
    currency = (budget_currency or goal.goal_spec.budget_currency).upper()
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
    validate_child_bounds(
        _goal_bounds(goal.goal_spec, program.authority.required_decision_gates),
        task_bounds,
        label="task",
    )
    return (
        CompiledTaskAuthority(
            version=_positive_int(version, "task authority version"),
            project_ref=project.reference(),
            program_ref=program.reference(),
            goal_ref=goal.reference(),
            provider_budget_minor_units=task_bounds.provider_budget_minor_units,
            provider_call_limit=task_bounds.provider_call_limit,
            budget_currency=task_bounds.budget_currency,
            task_spec=task,
        ),
        result,
    )
