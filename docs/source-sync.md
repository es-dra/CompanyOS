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
3. Update CompanyOS.
4. Run `.\bin\company-os.ps1 validate`.
5. Run `git diff --check`.
6. Commit with a scoped message.
7. Push to `main` or open a PR, depending on repository policy.

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

