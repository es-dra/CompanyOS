# CompanyOS Runtime Operations Runbook v0.2 Draft

Status: v0.2 pre-release, single host. Commands below perform no paid provider
call unless a future adapter is separately configured and granted. The bundled
demo uses only local SQLite databases.

## Prerequisites

- Python 3.11 or newer;
- `jsonschema` 4.18 or newer for repository contract validation; validation
  fails closed with an actionable error when it is unavailable;
- a local filesystem, not a network share, for the runtime database;
- restrictive filesystem permissions on `~/.company-os`;
- explicit project opt-in. Installing CompanyOS does not grant authority over
  unrelated projects.

From the repository:

```powershell
python -m pip install -e .
companyos-runtime --db "$HOME/.company-os/state/runtime.db" init
```

The module entry point works without installation:

```powershell
python -m companyos_runtime --db "$HOME/.company-os/state/runtime.db" init
```

## Safe Validation

Repository structure and JSON contracts:

```powershell
python -m companyos_runtime validate --repo .
```

Event integrity and replayed core projections:

```powershell
python -m companyos_runtime --db "$HOME/.company-os/state/runtime.db" verify
```

These commands provide structure/integrity evidence. They do not provide
provider smoke, human acceptance, or business validation.

## Zero-Cost Crash/Recovery Demo

Use a dedicated directory:

```powershell
python -m companyos_runtime demo `
  --state-dir "$HOME/.company-os/demos/crash-recovery" `
  --fault-at after_effect_before_checkpoint
```

Expected invariants in JSON output:

```text
simulated_crash_observed = true
run_state = delivered
task_state = delivered
effect_status = succeeded
external_effect_delta = 1
evidence_state = runtime_verification
improvement_state = owner_review
provider_cost = 0
```

Repeat with `before_effect`, `after_checkpoint`, and `none`. The claim is scoped
to the bundled fake provider and its idempotency ledger.

## Normal Intake

1. Write a human-facing Goal Contract and Task Packet.
2. Compile them to strict JSON `GoalSpec` and `TaskSpec` objects described by
   `runtime/contracts/v1/runtime-contracts.schema.json`.
3. Bootstrap the first local owner only on a new empty identity registry, then
   create role-bounded principals and authenticate short-lived sessions. Never
   fall back to caller-provided identity strings.
4. Create the goal, run, and task with unique idempotency keys and an
   authenticated session carrying the required role.
5. Apply `goal_compiled` and `run_ready`; a scheduler claim is forbidden while
   the parent Run is still `intake`, compiled-only, suspended, blocked,
   delivered, or improvement-pending.
6. Claim the Task (`ready -> leased`). Before `scheduler.start`, advance the
   Run with `task_started` using the exact live task/resource lease holder and
   fence. Only then may the scheduler move the Task to `running`.
7. Record a maker-checker approval and issue the narrow grant. Capability
   actions use a closed vocabulary; approval, grant, and consume each recheck
   TaskSpec scope, forbidden scope, live roles, and lifecycle in the same write
   transaction.
8. Declare each effect in TaskSpec with exact step, adapter, action, resource,
   and request digest; enqueue it through the outbox and revalidate before
   dispatch. Enqueue performs a non-consuming exact authority preflight so a
   non-holder or malformed grant cannot occupy the declared step. A worker
   consume additionally requires its current live
   `task://<task_id>` claim; a resource fence is still required when the
   resource itself has concurrent ownership.
9. Record typed artifacts/evidence, independent evaluation, Integration Queue
   state, and fresh observations. A delivered Task with declared workflow
   steps requires every declared step to have a durable successful result.
10. Let the Guard Resolver decide transitions from persisted facts.

Canceled, deleted, failed, or retired Tasks do not satisfy successful Run
delivery in v0.2; optional/superseded Task semantics are not yet defined.

Credentials and bearer session secrets must enter through a protected local
secret channel. Persisted principal and session tables contain derived hashes,
not reusable clear-text secrets. Disabling a principal or rotating a credential
revokes existing sessions; re-enabling a principal does not restore them.

The v0.2 draft does not expose command-line principal enrollment or bearer
session serialization as a release-ready surface. An integrating application
must authenticate through `IdentityManager` and pass the resulting opaque
`VerifiedPrincipal` to in-process kernel operations. Do not put credentials or
session secrets in command-line arguments, files, event payloads, or logs. A
display name or `--actor` string is not authentication.

## Status and Redaction

```powershell
python -m companyos_runtime --db .state/runtime.db status
python -m companyos_runtime --db .state/runtime.db status --run-id run-1
```

Status output contains counts and control projections, not event payloads,
context content, secrets, or raw provider responses. Treat the database itself
as sensitive because it may contain internal artifacts, approvals, and context.

For a machine-readable control-plane view:

```powershell
python -m companyos_runtime --db .state/runtime.db operator-snapshot
```

The snapshot verifies the event chain in one read transaction and returns only
schema/event-head digests, state counts, lease/outbox/integration/evaluation/
approval/negative-result counts, and observation freshness. It does not emit
event payloads, context, requests, receipts, secrets, raw errors, or provider
responses. It is not a runtime process probe, provider health check, alerting
system, or production-readiness verdict.

## Restart Recovery

The v0.2 draft intentionally has no unauthenticated recovery CLI. A trusted
kernel process may call `DurableWorkflow.recover_pending()` only after its
composition root has authenticated the process identity and opened the exact
adapter/state pair. Keep that operation behind the same OS account and ACL as
the runtime database.

A real adapter must implement:

- stable idempotency keys;
- request-digest verification;
- receipt lookup/reconciliation;
- clear success, failure, unknown, and retryable states;
- bounded retry and circuit-breaker policy;
- redaction and cost reporting;
- conformance tests for all crash windows.

Recovery records authorization failures as failed receipts and negative
results, then continues scanning later effects. One revoked or stale-fence
effect must not starve unrelated valid work. A terminal Task or sealed Run
cannot authorize a new external call. If provider lookup proves the exact
effect already happened before sealing, recovery may checkpoint that existing
receipt; this is reconciliation, not new execution.

Do not automatically retry an unknown non-idempotent external side effect.
Route it to `blocked_with_decision`.

## Projection Drift

First verify:

```powershell
python -m companyos_runtime --db .state/runtime.db verify
```

If the event chain passes but a core projection differs, make a backup. The
trusted application may call
`ProjectionReplayer(store).repair(actor=system_session)` with an authenticated
`system` session. There is no public repair CLI in v0.2.

Repair replays Goal/Run/Task projections. It refuses to delete unexpected rows
without events. If the event chain itself fails, stop writes, preserve the DB
and WAL files, and investigate; do not "repair" hashes in place.

## Backup and Restore

Create an online SQLite snapshot and a bound verification manifest:

```powershell
python -m companyos_runtime --db .state/runtime.db backup `
  --target .backups/runtime-001.db
```

The command refuses an existing backup or manifest. It verifies SQLite
`integrity_check`, schema revision/checksum, the global event chain, and core
projection replay/readback before reporting success. The JSON output and
manifest expose counts and digests, not source/target paths or file names.

Restore defaults to a new sibling named `<backup>.restored.db`; an explicit
new target is clearer for drills:

```powershell
python -m companyos_runtime restore `
  --backup .backups/runtime-001.db `
  --target .restore-tests/runtime.db
```

Restore rejects an existing target, symlink, or existing `-wal`, `-shm`, or
`-journal` sidecar. Before writing it validates the manifest and source backup;
after writing it reruns SQLite integrity, event-chain verification, and core
projection replay/readback. A failed restore removes only the new files it
created and never overwrites unknown state.

The runtime backup does **not** include external adapter receipt/idempotency
ledgers. Its manifest therefore records `recovery_set.complete = false`. Keep
every enabled adapter ledger, keys/configuration needed to interpret receipts,
and the runtime database in one governed recovery set. Until that complete set
has been restored and reconciled in a drill, do not claim disaster recovery or
exact external-effect recovery.

The manifest and backup digest detect mismatch only when the manifest itself is
trusted. They are not externally signed, hardware-attested, or proof of
power-loss durability. Store them under independent access controls and add an
external signature/custody record before making a cryptographic backup claim.

Never place live SQLite WAL files on a network share. Do not use filesystem
sync as multi-host coordination.

## Adapter Conformance

The reusable protocol and harness are documented in
`docs/adapter-conformance.md`. The bundled offline check is:

```powershell
python -m companyos_runtime adapter-conformance `
  --state-dir .state/adapter-conformance
```

This creates one fake-adapter effect. A real project adapter requires a
separately authorized isolated fixture, provider-specific crash tests, cost and
redaction gates, an external receipt-ledger recovery plan, and an independent
evaluator. The common report alone is not provider smoke or production proof.

## Incident Routes

| Condition | Required route |
|---|---|
| Event hash or payload digest mismatch | Stop writes; preserve evidence; owner decision |
| Event insert is not armed by the store-managed connection | Reject it; investigate direct-driver or process-boundary misuse |
| Session invalid, expired, or revoked | Re-authenticate; never substitute a display name or principal string |
| Principal disabled or missing role | Owner reviews identity/role assignment; do not widen the operation |
| Projection mismatch, valid event chain | Backup; replay/repair core projections |
| Stale lease/fence | Reject worker; acquire a new fence after expiry/release |
| Grant expired/revoked/exhausted | New exact approval/grant; never widen existing grant |
| Unknown external effect | Reconcile by receipt; otherwise block, do not blind retry |
| Repeated failure fingerprint | Open circuit; retain negative result; select repair route |
| Runtime observation stale/unhealthy | Mark runtime stale; probe/restart/redeploy as appropriate |
| Held-out safety failure | Reject candidate; preserve eval result |
| Limited request lacks delivered real Run/Task or typed accepted PASS evidence | Keep owner_review; collect real bounded-task evidence |
| Limited source environment/kind/URI is non-real or unknown after canonical classification | Deny limited promotion; replace it with traceable allowlisted real-task evidence |
| Protected event lacks exact service capability/config lineage | Stop promotion writes; preserve the database; investigate process/config drift |
| Verifier lacks a key/configuration-scoped authority ID or its implementation/config drifts | Refuse registry startup; migrate trust configuration explicitly rather than relabeling it |
| Sealed custody verifier absent, invalid, or mismatched | Deny active promotion; never substitute local test custody |
| Custody projection exists without its unique protected source event | Treat as integrity failure; do not repair it into authority |
| Context or memory provenance changed | Reassemble/re-evaluate; block promotion |
| Server/provider/public action requested | Require separately scoped authority and evaluator |

## Release Gate

Before any release claim, require:

1. clean repository and known branch/upstream;
2. full unit/contract/chaos/concurrency suite passing;
3. identity/session/role forgery and revocation tests passing;
4. repository validation and event/projection verification;
5. adapter conformance for every enabled side-effect surface;
6. evidence level stated precisely with non-claims;
7. no secrets/private COS material in the public projection;
8. explicit authority for remote push, server write, provider cost, public
   release, destructive cleanup, and active-rule promotion;
9. independent evaluator outcome;
10. rollback, backup, and handoff recorded.

Repository CI defines Windows and Ubuntu jobs for Ruff format/lint, mypy, the
full unittest suite, repository contract validation, and clean installed-root
validation. A workflow file existing locally is structure verification only;
the gate becomes CI evidence only after the workflow runs on the exact commit.
