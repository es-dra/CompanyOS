# API Contract Standard

Every API change must be contract-first.

## Required Fields

- Method and path.
- Request schema.
- Response schema.
- Error shape.
- Auth or permission requirement.
- Idempotency rule.
- Pagination, filtering, and sorting rule for list endpoints.
- Version or migration impact.
- Frontend fixture or mock path.
- Contract test or smoke command.

## Response Boundary

API responses may expose:

- stable IDs;
- status;
- safe summaries;
- artifact manifests;
- user-safe error codes and messages;
- timestamps and version fields when useful.

API responses must not expose:

- provider secrets;
- raw provider responses;
- local absolute paths;
- signed URLs unless explicitly intended and scoped;
- private exception stacks;
- database internals;
- customer material or real costs;
- generated media bytes.

## Error Shape

Use one stable error envelope per service:

```json
{
  "error": {
    "code": "string",
    "message": "user-safe message",
    "request_id": "optional trace id"
  }
}
```

Internal traces belong in logs, not public API responses.

## Contract Change Checklist

- Backward compatible or migration documented.
- Frontend fixture updated.
- Tests updated.
- Release or handoff note names the contract change.
- Rollback behavior is understood.
