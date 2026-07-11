"""Command-line adapter for the CompanyOS Runtime Kernel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .adapters import run_adapter_conformance
from .backup import create_online_backup, restore_backup
from .compiler import compile_goal, compile_task
from .demo import FAULT_POINTS, run_zero_cost_demo
from .errors import RuntimeKernelError
from .fake_provider import FakeProvider
from .kernel import RuntimeKernel
from .operator import operator_snapshot
from .replay import ProjectionReplayer
from .store import SQLiteStore
from .types import GoalSpec
from .validation import validate_repository


DEFAULT_HOME = Path.home() / ".company-os"
DEFAULT_DB = DEFAULT_HOME / "state" / "runtime.db"


def _json_file(value: str) -> dict[str, Any]:
    if value == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(value).expanduser().read_text(encoding="utf-8-sig")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("JSON input must be an object")
    return result


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _store(args: argparse.Namespace) -> SQLiteStore:
    store = SQLiteStore(args.db)
    store.initialize()
    return store


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="companyos-runtime",
        description="Durable, fail-closed CompanyOS single-host runtime kernel",
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite runtime database")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="initialize the local runtime database")

    compile_goal_parser = commands.add_parser(
        "compile-goal", help="compile a human Goal Contract to GoalSpec"
    )
    compile_goal_parser.add_argument("--input", required=True)

    compile_task_parser = commands.add_parser(
        "compile-task", help="compile a human Task Packet to TaskSpec"
    )
    compile_task_parser.add_argument("--input", required=True)
    compile_task_parser.add_argument("--goal-spec", required=True)

    validate = commands.add_parser(
        "validate", help="validate repository contracts without network/provider calls"
    )
    validate.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))

    demo = commands.add_parser(
        "demo", help="run the zero-cost crash/recovery vertical slice"
    )
    demo.add_argument("--state-dir", required=True)
    demo.add_argument(
        "--fault-at",
        choices=sorted(item for item in FAULT_POINTS if item is not None) + ["none"],
        default="after_effect_before_checkpoint",
    )

    verify = commands.add_parser(
        "verify", help="verify event integrity and core projections"
    )
    verify.add_argument("--events-only", action="store_true")

    status = commands.add_parser(
        "status", help="show redacted runtime counts and optional run projection"
    )
    status.add_argument("--run-id")

    backup = commands.add_parser(
        "backup", help="create a verified online backup and manifest"
    )
    backup.add_argument("--target", required=True)
    backup.add_argument("--manifest")

    restore = commands.add_parser(
        "restore", help="restore a verified backup into a new database only"
    )
    restore.add_argument("--backup", required=True)
    restore.add_argument("--manifest")
    restore.add_argument("--target")

    commands.add_parser(
        "operator-snapshot",
        help="emit a redacted counts/digests/freshness control snapshot",
    )

    conformance = commands.add_parser(
        "adapter-conformance",
        help="run the zero-cost bundled adapter conformance harness",
    )
    conformance.add_argument("--adapter", choices=["fake"], default="fake")
    conformance.add_argument("--state-dir", required=True)

    return parser


def _dispatch(args: argparse.Namespace) -> Any:
    if args.command == "validate":
        return validate_repository(args.repo)
    if args.command == "demo":
        fault = None if args.fault_at == "none" else args.fault_at
        return run_zero_cost_demo(args.state_dir, fault_at=fault)
    if args.command == "compile-goal":
        _, compilation = compile_goal(_json_file(args.input))
        return compilation.__dict__
    if args.command == "compile-task":
        goal = GoalSpec.from_dict(_json_file(args.goal_spec))
        _, compilation = compile_task(_json_file(args.input), goal=goal)
        return compilation.__dict__
    if args.command == "backup":
        return create_online_backup(args.db, args.target, manifest_path=args.manifest)
    if args.command == "restore":
        return restore_backup(
            args.backup,
            manifest_path=args.manifest,
            target_database=args.target,
        )
    if args.command == "operator-snapshot":
        return operator_snapshot(args.db)
    if args.command == "adapter-conformance":
        state_dir = Path(args.state_dir).expanduser().resolve()
        provider = FakeProvider(state_dir / "fake-adapter.db")
        provider.initialize()
        return run_adapter_conformance(
            provider, adapter_name=provider.adapter_id
        ).to_wire()
    store = _store(args)
    kernel = RuntimeKernel(store)
    if args.command == "init":
        return {
            "database": str(store.path),
            "status": "initialized",
            "mode": "single_host",
        }
    if args.command == "verify":
        event_count = store.verify_event_chain()
        output: dict[str, Any] = {
            "database": str(store.path),
            "event_chain_length": event_count,
        }
        if not args.events_only:
            replayed = ProjectionReplayer(store).verify()
            output["core_projections"] = {
                "goals": len(replayed.goals),
                "runs": len(replayed.runs),
                "tasks": len(replayed.tasks),
            }
        output["status"] = "passed"
        return output
    if args.command == "status":
        tables = (
            "goals",
            "runs",
            "tasks",
            "events",
            "outbox",
            "evidence_claims",
            "runtime_observations",
            "integration_items",
            "improvement_proposals",
        )
        output = {
            "database": str(store.path),
            "counts": {
                table: store.query(f"SELECT COUNT(*) AS count FROM {table}")[0]["count"]
                for table in tables
            },
        }
        if args.run_id:
            output["run"] = kernel.get_run(args.run_id)
        return output
    raise ValueError(f"unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        result = _dispatch(parser.parse_args(argv))
        _emit(result)
        return 0
    except (RuntimeKernelError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
