"""Independent evaluator tests for lexical scope and Goal/Task containment."""

from __future__ import annotations

import unittest
from typing import Any

from companyos_runtime.errors import ContractError
from companyos_runtime.scope import (
    normalize_scope,
    scope_allowed,
    scope_covers,
    scopes_overlap,
    validate_goal_scope,
    validate_task_within_goal,
)
from companyos_runtime.types import (
    Capability,
    EvidenceState,
    GoalSpec,
    RuntimeSurfaceSpec,
    TaskSpec,
)


class ScopeNormalizationTests(unittest.TestCase):
    def test_scope_coverage_is_segment_safe(self) -> None:
        self.assertTrue(scope_covers("/repo/app", "/repo/app/module/file.py"))
        self.assertTrue(scope_covers("/repo/app/**", "/repo/app/module/file.py"))
        self.assertFalse(scope_covers("/repo/app", "/repo/application/file.py"))
        self.assertFalse(scope_covers("/repo/app", "/repo/app2/file.py"))
        self.assertFalse(scope_covers("resource://one", "resource://one-more"))
        self.assertTrue(scope_covers("resource://one", "resource://one/child"))
        self.assertTrue(
            scope_allowed(["/repo/app/**", "/repo/docs/**"], "/repo/docs/index.md")
        )
        self.assertFalse(scope_allowed(["/repo/app/**"], "/repo/application/file.py"))

    def test_normalization_handles_windows_separators_without_losing_boundary(
        self,
    ) -> None:
        self.assertEqual(normalize_scope("C:\\Projects\\App\\"), "c:/Projects/App")
        self.assertTrue(
            scope_covers(r"C:\Projects\App\**", r"c:\Projects\App\src\main.py")
        )
        self.assertFalse(
            scope_covers(r"C:\Projects\App\**", r"c:\Projects\Application\main.py")
        )

    def test_dot_dot_and_unsupported_wildcards_are_rejected(self) -> None:
        unsafe = (
            "../secret",
            "/repo/app/../secret",
            r"C:\repo\app\..\secret",
            "resource://host/root/../secret",
            "/repo/*/secret",
            "/repo/**/secret",
        )
        for value in unsafe:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ContractError, "unsafe or unsupported scope"
                ):
                    normalize_scope(value)

    def test_percent_encoded_dot_dot_uri_segments_are_rejected(self) -> None:
        for value in (
            "https://example.test/root/%2e%2e/secret",
            "https://example.test/root/%2E%2E/secret",
            "https://example.test/root/%2e./secret",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ContractError, "unsafe or unsupported scope"
                ):
                    normalize_scope(value)

    def test_overlap_uses_segment_containment(self) -> None:
        self.assertTrue(scopes_overlap("/repo/app/**", "/repo/app/private/**"))
        self.assertFalse(scopes_overlap("/repo/app/**", "/repo/application/**"))


class GoalTaskContainmentTests(unittest.TestCase):
    API_SURFACE = RuntimeSurfaceSpec(
        surface_key="service:api",
        target_identity="commit:abc123",
        allowed_probes=("process_commit_probe",),
        max_ttl_seconds=60,
        trigger_event_required=True,
    )

    @staticmethod
    def _goal(**overrides) -> GoalSpec:
        values: dict[str, Any] = {
            "goal_id": "goal-1",
            "target_outcome": "bounded execution",
            "success_evidence_states": (EvidenceState.RUNTIME,),
            "read_scope": ("/workspace/project/public/**",),
            "write_scope": ("/workspace/project/output/**",),
            "forbidden_scope": ("/workspace/project/secrets/**",),
            "allowed_capabilities": (Capability.READ_LOCAL, Capability.WRITE_LOCAL),
            "required_runtime_surfaces": (GoalTaskContainmentTests.API_SURFACE,),
        }
        values.update(overrides)
        return GoalSpec(**values)

    @staticmethod
    def _task(**overrides) -> TaskSpec:
        values: dict[str, Any] = {
            "task_id": "task-1",
            "goal_id": "goal-1",
            "objective": "bounded task",
            "expected_delta": "quality",
            "primary_surface": "artifact://report",
            "evidence_target": EvidenceState.RUNTIME,
            "capabilities": (Capability.READ_LOCAL,),
            "read_scope": ("/workspace/project/public/docs/**",),
            "write_scope": ("/workspace/project/output/reports/**",),
            "required_runtime_surfaces": (GoalTaskContainmentTests.API_SURFACE,),
        }
        values.update(overrides)
        return TaskSpec(**values)

    def test_task_within_goal_authority_is_accepted(self) -> None:
        goal = self._goal()
        task = self._task()
        validate_goal_scope(goal)
        validate_task_within_goal(goal, task)

    def test_goal_scope_cannot_overlap_its_forbidden_scope(self) -> None:
        goal = self._goal(
            read_scope=("/workspace/project/**",),
            forbidden_scope=("/workspace/project/secrets/**",),
        )
        with self.assertRaisesRegex(
            ContractError, "goal read_scope intersects forbidden"
        ):
            validate_goal_scope(goal)

    def test_task_scope_cannot_overlap_task_forbidden_scope(self) -> None:
        task = self._task(
            forbidden_scope=("/workspace/project/public/docs/private/**",),
        )
        with self.assertRaisesRegex(
            ContractError, "task read_scope intersects forbidden"
        ):
            validate_task_within_goal(self._goal(), task)

    def test_task_capability_cannot_exceed_goal_authority(self) -> None:
        goal = self._goal(allowed_capabilities=(Capability.READ_LOCAL,))
        task = self._task(capabilities=(Capability.READ_LOCAL, Capability.WRITE_LOCAL))
        with self.assertRaisesRegex(
            ContractError, "capabilities exceed goal authority"
        ):
            validate_task_within_goal(goal, task)

    def test_task_read_and_write_scopes_cannot_exceed_goal_authority(self) -> None:
        cases = (
            (
                "read_scope",
                ("/workspace/project/publication/report.md",),
                "read_scope exceeds",
            ),
            (
                "write_scope",
                ("/workspace/project/outputs/report.md",),
                "write_scope exceeds",
            ),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ContractError, message):
                    validate_task_within_goal(
                        self._goal(), self._task(**{field: value})
                    )

    def test_task_runtime_surface_cannot_exceed_goal_contract(self) -> None:
        task = self._task(
            required_runtime_surfaces=(
                self.API_SURFACE,
                RuntimeSurfaceSpec(
                    surface_key="server:prod",
                    target_identity="release:2026-07-10",
                    allowed_probes=("deployment_probe",),
                ),
            )
        )
        with self.assertRaisesRegex(
            ContractError, "runtime surfaces exceed goal contract"
        ):
            validate_task_within_goal(self._goal(), task)

    def test_task_goal_identity_must_match_the_containing_goal(self) -> None:
        with self.assertRaisesRegex(ContractError, "goal"):
            validate_task_within_goal(self._goal(), self._task(goal_id="goal-other"))


if __name__ == "__main__":
    unittest.main()
