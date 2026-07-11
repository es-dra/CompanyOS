# Project Adapter Conformance v0.2 Draft

`DurableWorkflow` accepts a minimal `WorkflowAdapter` protocol. A project
adapter must provide:

```python
initialize() -> None
execute(project_id, idempotency_key, effect_id, request_digest, request) -> AdapterReceipt
lookup(project_id, idempotency_key, effect_id, request_digest) -> AdapterReceipt | None
```

The adapter also exposes a read-only `adapter_id`. That identity must exactly
match the adapter declared by the compiled workflow step; aliases and runtime
renaming fail closed.

`execute` may create the external effect. `lookup` must only reconcile an
already committed effect. Both operations bind project, idempotency key,
effect identity, and request digest. Reuse with another effect, digest, or
request must fail closed.

Every receipt carries `adapter_id`, `project_id`, `idempotency_key`, `effect_id`,
`request_digest`, terminal `status`, and `closed=True`. The workflow verifies
all of those fields before checkpointing. Adapter lookup is reached only after
the persisted compiled-step binding is verified and the exact authority use is
durably consumed.

Legacy fake-provider rows are quarantined under `__legacy__`. They are invisible
to project lookups until initialization receives an explicit per-idempotency-key
mapping such as `legacy_project_migrations={"old-key": "project-id"}`. This
mapping is migration evidence, not an inferred project assignment.

## Reusable Harness

The Python API is intended for an explicitly isolated project-adapter fixture:

```python
from companyos_runtime import run_adapter_conformance

report = run_adapter_conformance(
    sandbox_adapter,
    adapter_name="project-sandbox-adapter",
)
assert report.status == "passed"
```

The harness creates one adapter effect. A project must independently authorize
and isolate any network, remote write, or provider-cost surface before calling
it. Never point the harness at production data or a non-idempotent adapter.

The bundled fake adapter can be checked without network or provider cost:

```powershell
python -m companyos_runtime adapter-conformance `
  --state-dir "$HOME/.company-os/demos/adapter-conformance"
```

The report requires a successful durable first receipt, exact lookup,
idempotent replay, stable receipt identity, cross-project key isolation, and
typed rejection of changed request, effect identity, or digest. An unexpected
adapter exception is a conformance failure, not a successful denial. It is
local runtime verification. It does not prove provider production health,
provider-wide exactly-once behavior, multi-host delivery, product quality, or
business validation.

## Project Adoption Gate

For each real adapter, retain:

- the adapter implementation/configuration digest;
- the isolated fixture and exact conformance report;
- supported receipt states and unknown-result route;
- timeout, retry, circuit-breaker, redaction, and integer-cost policy;
- rollback or compensation route;
- companion receipt/idempotency state included in the recovery set;
- an independent evaluator outcome before enabling the capability.

Passing the common harness is necessary but not sufficient. Provider-specific
failure modes and all documented crash windows still require dedicated tests.
