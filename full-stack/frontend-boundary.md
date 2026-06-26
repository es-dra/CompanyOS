# Frontend Boundary Standard

Frontend code should be built around product workflows and stable service
contracts, not backend internals.

## Frontend May Use

- API method and path.
- Request and response schemas.
- Stable IDs.
- Safe summaries.
- Artifact manifests.
- Public-safe status fields.
- User-safe error codes and messages.
- Pagination, sorting, and filtering contracts.

## Frontend Must Not Use

- Database table or column names as product logic.
- CLI internal orchestration details.
- Provider secrets or provider raw responses.
- Local absolute paths.
- Signed URLs unless the API explicitly returns them for that UI purpose.
- Private backend exception stacks.
- Generated media bytes stored directly in application state.

## Required UI States

Every user-facing workflow must define:

- loading;
- empty;
- error;
- success;
- disabled or pending action;
- retry when recoverable;
- stale or polling state when background jobs are involved.

## Browser Smoke

When a user-facing flow changes, verify at least:

- first render is not blank;
- primary action can be reached;
- API failure has a visible safe error;
- long text does not break the layout;
- no secret, raw provider response, private path, or signed URL is visible.
