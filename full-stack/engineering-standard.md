# Full-Stack Engineering Standard

This is the public CompanyOS engineering standard for professional software
development. It applies to frontend, backend, runtime services, data changes,
agent harnesses, and release work.

It is intentionally framework-neutral. Project-local instructions and framework
docs still decide implementation details.

## Default Delivery Order

```text
problem and acceptance
  -> contract / schema / route
  -> deterministic harness or fixture
  -> implementation
  -> tests and smoke
  -> evidence record
  -> release or handoff
```

Do not start with UI polish, model output, or broad refactors before the contract
and acceptance boundary are clear.

## Required Before Editing

- Goal.
- Non-goals.
- Read scope.
- Write scope.
- Contract or schema touched.
- Verification command.
- Release or handoff target.
- Provider, network, download, or destructive-operation gate.

## Frontend Standard

User-facing work must cover:

- loading state;
- empty state;
- error state;
- success state;
- disabled or pending action state;
- retry path when the failure is recoverable;
- stable layout across expected viewport sizes;
- user-safe copy;
- no secret, private path, raw provider response, or signed URL in UI.

Frontend code should depend on API contracts, safe summaries, stable IDs, and
artifact manifests. It should not depend on database tables, CLI internals,
provider secrets, or backend private exception details.

## Backend Standard

Backend work must cover:

- input validation;
- auth or permission check when needed;
- deterministic error shape;
- structured logs without secrets;
- timeout and retry policy for external calls;
- provider/tool gate when external capability is used;
- public-safe API responses;
- focused test or smoke command.

Long-running work must expose a job ID, status state, failure state, artifact or
report path, and retry/cancel policy when applicable.

## Data Standard

Persistent data changes must define:

- schema and migration path;
- indexes for expected queries;
- transaction boundary;
- uniqueness and idempotency;
- seed or fixture data;
- backup or export path when data has value;
- rollback effect;
- PII and secret handling.

Do not mix temporary runtime output, caches, raw provider responses, or generated
media bytes into durable business data.

## Testing Matrix

| Layer | Required when |
|---|---|
| unit test | deterministic transformation or boundary logic |
| contract test | API, schema, artifact manifest, provider adapter |
| integration test | multiple modules or service boundary |
| browser / UI smoke | user-facing flow changed |
| migration test | persistent schema changed |
| security check | auth, upload, external URL, or secret handling changed |
| release smoke | public repo, deployment, or handoff target changed |

When verification cannot run, record why and what residual risk remains.

## Maintainability

- Ideal file size is under 300 lines.
- 301-500 lines require maintenance review.
- Over 500 lines require a split plan or explicit reason.
- A new module must have one responsibility that can be stated in one sentence.
- Do not mix API route, job orchestration, artifact store, provider adapter,
  report writer, and UI render logic in one file.
- Do not keep parallel `new`, `fixed`, `v2`, or `enhanced` paths without a
  migration and retirement condition.
