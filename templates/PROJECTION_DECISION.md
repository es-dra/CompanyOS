# Projection Decision

Use this before projecting private COS source material into CompanyOS.

## Source

- source object:
- source status:
- source layer:
- source path:
- projection target:
- projected as:

## Public-Safe Check

- public safe: yes/no
- redaction status: redacted / requires_review / blocked
- private material risk:
- project-specific material:
- candidate public boundary: not_candidate / template_only / feedback_shape_only / schema_under_review_only / sanitized_example_only / blocked
- misleading identity risk:
- release boundary:

## Decision

- decision: project / defer / block
- owner review:
- validation command:

## Boundary

Candidate source material may become a public-safe template, schema, adapter
instruction, or feedback shape. It must not be represented as an active
CompanyOS rule unless the private source rule is active or explicitly approved
for projection.

CompanyOS receives only the public-safe projected mechanism. It does not expose
private COS source passages, internal strategy, customer material, provider raw
responses, research trails, or candidate rationale.

## Machine-Readable Minimum

Projection decision records should satisfy:

```text
runtime/projection-decision.schema.json
```
