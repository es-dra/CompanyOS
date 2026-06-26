# Source Sync

CompanyOS is a public-safe projection of a private Company OS source knowledge
base. The private source stays outside this repository.

## Layer Model

```text
private source knowledge base
  -> curated CompanyOS projection
  -> installed developer machines
  -> sanitized feedback export
  -> human-reviewed source update candidate
```

## What Belongs Here

- Public-safe engineering rules.
- Startup contracts.
- Evidence-state rules.
- Feedback templates.
- Schemas and validators.
- Adapter instructions.
- Install and onboarding docs.
- Sanitized examples.

## What Does Not Belong Here

- Secrets, tokens, cookies, provider keys.
- Signed URLs.
- Raw provider responses.
- Customer material.
- Real costs.
- Private contracts.
- Unpublished strategy.
- Internal retrospectives.
- Generated media bytes or private source assets.

## Change Flow

For maintainers:

1. Update the private source rule when the change is a source-rule change.
2. Decide which parts are public-safe.
3. Record or draft a projection decision using `templates/PROJECTION_DECISION.md`.
4. Update CompanyOS.
5. Run `.\bin\company-os.ps1 validate`.
6. Run `git diff --check`.
7. Commit with a scoped message.
8. Push to `main` or open a PR, depending on repository policy.

For external contributors:

1. Open an issue or PR against CompanyOS.
2. Keep changes public-safe.
3. Do not propose changes that require private source material to understand.
4. Treat feedback as candidate input, not automatic rule promotion.

## Feedback Route

Feedback should identify:

- the project or task context;
- the rule or template that helped or blocked work;
- evidence of the problem or success;
- the proposed change;
- whether the feedback is project-specific or generally reusable.

Maintainers decide whether feedback becomes a source update, a public projection
change, a project-local note, or no change.

## Projection Decision

Before private COS material becomes CompanyOS content, decide:

- whether the source object is active, limited, candidate, template, or draft;
- which private source layer it comes from;
- whether the target is a runtime-kit object, template, schema, adapter, or
  sanitized example;
- what the public object is projected as;
- whether the content is public-safe after redaction;
- whether candidate material is bounded as template-only, feedback-shape-only,
  schema-under-review-only, sanitized-example-only, or blocked;
- whether it would mislead users into treating CompanyOS as the full private
  COS source;
- which release boundary prevents overclaiming;
- which validation command proves the projected object is structurally usable.

Candidate material may become a public-safe template, schema, adapter note, or
feedback shape. It must not become an active CompanyOS rule unless maintainers
have approved that projection.

Projection decision records should satisfy:

```text
runtime/projection-decision.schema.json
```

Maintainers can draft a local decision record with:

```powershell
.\bin\company-os.ps1 new-projection -SourceObject "<source>" -SourceStatus template -SourceLayer distribution_projection -ProjectionTarget "<target>" -ProjectedAs template -CandidatePublicBoundary not_candidate
```

CompanyOS should expose the resulting runtime mechanism, not the private source
reasoning, internal research trail, unpublished strategy, or candidate
rationale.
