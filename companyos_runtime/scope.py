"""Segment-safe scope normalization and Goal/Task contract containment."""

from __future__ import annotations

import posixpath
import re
from urllib.parse import unquote
from collections.abc import Iterable

from .errors import ContractError
from .types import GoalSpec, RuntimeSurfaceSpec, TaskSpec


_DRIVE = re.compile(r"^[A-Za-z]:/")


def normalize_scope(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError("scope must be a non-empty string")
    raw = value.strip().replace("\\", "/")
    for _ in range(20):
        decoded = unquote(raw).replace("\\", "/")
        if decoded == raw:
            break
        raw = decoded
    else:
        raise ContractError(f"scope has excessive nested encoding: {value}")
    recursive = raw.endswith("/**")
    body = raw[:-3] if recursive else raw
    if (
        "\x00" in body
        or "*" in body
        or "?" in body
        or "#" in body
        or any(part == ".." for part in body.split("/"))
    ):
        raise ContractError(f"unsafe or unsupported scope: {value}")
    if "://" in body:
        scheme, rest = body.split("://", 1)
        if not scheme or not rest:
            raise ContractError(f"invalid scope URI: {value}")
        normalized = f"{scheme.lower()}://{posixpath.normpath('/' + rest).lstrip('/')}"
    else:
        normalized = posixpath.normpath(body)
        if _DRIVE.match(normalized):
            normalized = normalized[0].lower() + normalized[1:]
    normalized = normalized.rstrip("/") or "/"
    return normalized + ("/**" if recursive else "")


def scope_covers(allowed: str, candidate: str) -> bool:
    parent = normalize_scope(allowed)
    child = normalize_scope(candidate)
    if parent.endswith("/**"):
        parent = parent[:-3].rstrip("/")
    if child.endswith("/**"):
        child = child[:-3].rstrip("/")
    if _DRIVE.match(parent) and _DRIVE.match(child):
        parent = parent.casefold()
        child = child.casefold()
    if parent == child:
        return True
    if parent == "/":
        return child.startswith("/")
    return child.startswith(parent + "/")


def scope_allowed(allowed_scopes: Iterable[str], candidate: str) -> bool:
    return any(scope_covers(parent, candidate) for parent in allowed_scopes)


def scopes_overlap(left: str, right: str) -> bool:
    return scope_covers(left, right) or scope_covers(right, left)


def _reject_forbidden(
    scopes: Iterable[str], forbidden: Iterable[str], label: str
) -> None:
    conflicts = [
        (scope, denied)
        for scope in scopes
        for denied in forbidden
        if scopes_overlap(scope, denied)
    ]
    if conflicts:
        raise ContractError(f"{label} intersects forbidden scope: {conflicts}")


def validate_goal_scope(spec: GoalSpec) -> None:
    if not all(
        isinstance(item, RuntimeSurfaceSpec) for item in spec.required_runtime_surfaces
    ):
        raise ContractError(
            "required_runtime_surfaces must contain RuntimeSurfaceSpec objects"
        )
    from .types import Capability

    if Capability.PROVIDER_COST in spec.allowed_capabilities and (
        spec.provider_call_limit < 1 or spec.provider_budget_minor_units < 0
    ):
        raise ContractError(
            "provider_cost authority requires explicit provider_call_limit and minor-unit budget"
        )
    for value in (*spec.read_scope, *spec.write_scope, *spec.forbidden_scope):
        normalize_scope(value)
    _reject_forbidden(spec.read_scope, spec.forbidden_scope, "goal read_scope")
    _reject_forbidden(spec.write_scope, spec.forbidden_scope, "goal write_scope")


def validate_task_within_goal(goal: GoalSpec, task: TaskSpec) -> None:
    validate_goal_scope(goal)
    if task.goal_id != goal.goal_id:
        raise ContractError(
            f"task goal_id does not match containing goal: {task.goal_id} != {goal.goal_id}"
        )
    for value in (*task.read_scope, *task.write_scope, *task.forbidden_scope):
        normalize_scope(value)
    missing_capabilities = set(task.capabilities) - set(goal.allowed_capabilities)
    if missing_capabilities:
        raise ContractError(
            "task capabilities exceed goal authority: "
            + ", ".join(sorted(item.value for item in missing_capabilities))
        )
    uncovered_reads = [
        item for item in task.read_scope if not scope_allowed(goal.read_scope, item)
    ]
    uncovered_writes = [
        item for item in task.write_scope if not scope_allowed(goal.write_scope, item)
    ]
    if uncovered_reads:
        raise ContractError(
            f"task read_scope exceeds goal authority: {uncovered_reads}"
        )
    if uncovered_writes:
        raise ContractError(
            f"task write_scope exceeds goal authority: {uncovered_writes}"
        )
    combined_forbidden = (*goal.forbidden_scope, *task.forbidden_scope)
    _reject_forbidden(task.read_scope, combined_forbidden, "task read_scope")
    _reject_forbidden(task.write_scope, combined_forbidden, "task write_scope")
    goal_surfaces = {item.surface_key: item for item in goal.required_runtime_surfaces}
    undeclared_surfaces = [
        item.surface_key
        for item in task.required_runtime_surfaces
        if goal_surfaces.get(item.surface_key) != item
    ]
    if undeclared_surfaces:
        raise ContractError(
            f"task runtime surfaces exceed goal contract: {sorted(undeclared_surfaces)}"
        )
