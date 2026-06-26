# Redaction Policy

Feedback exports must remove or block:

- provider keys, tokens, cookies, and credentials;
- signed URLs and private download URLs;
- local absolute paths unless intentionally normalized;
- customer names, private contracts, pricing, and real costs;
- unpublished strategy or partner judgments;
- raw provider responses;
- generated media bytes and private source assets;
- private retrospectives.

If a record cannot be safely redacted, mark the export item as
`requires_review` or `blocked`.

## Projection Redaction Checklist

Before adding or exporting material, check:

- no private Company OS source passages are copied verbatim;
- no customer, contract, real cost, or unpublished strategy appears;
- no provider key, token, cookie, signed URL, raw response, or private endpoint
  appears;
- no generated media bytes, private assets, or local private absolute paths are
  included;
- candidate material is not represented as an active rule;
- private source rationale, research trails, and unpublished strategy are not
  copied into the public projection.

When any item is uncertain, set redaction status to `requires_review`. When it
cannot be safely normalized, set it to `blocked`.
