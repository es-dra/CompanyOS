# Full-Stack Release Checklist

Release is not the same as merge. A release hands a verified capability to a
target user, downstream developer, demo surface, or production environment.

## Before Release

- Target user or recipient is named.
- Included changes are named.
- Excluded changes are named.
- Contract/schema changes are named.
- Verification commands passed or residual risk is recorded.
- Migration and rollback behavior are understood.
- Secrets and private material scan is complete.
- Handoff or release note is written.

## Verification Evidence

Record the highest evidence state reached:

- structure verification;
- runtime verification;
- provider smoke;
- human acceptance;
- business validation.

Do not claim a higher state from a lower one.

## Rollback

Know:

- rollback commit or artifact;
- generated files safe to delete;
- persistent data that must not be edited directly;
- users, agents, or downstream teams that need notice.

## Public Repository Gate

Before publishing or tagging a public repo:

- no secrets;
- no private source vault material;
- no customer details;
- no real costs;
- no raw provider responses;
- no generated media bytes;
- license present;
- README explains install and scope;
- validation command passes.
