# Authority Order

When a task uses this runtime kit, apply instructions in this order:

```text
owner/company source rules
  -> CompanyOS
  -> project-local instructions
  -> task startup packet
  -> current user request
```

The runtime kit is a projection layer. It does not override private source
rules, project-local safety instructions, or human review requirements.

## Default Read Set

Start with the smallest useful context:

- this authority order;
- `core/evidence-states.md`;
- `gfr/startup-contract.md`;
- relevant project-local instructions;
- current task request.

Do not load private archives, old drafts, secrets, customer files, or generated
media unless the task explicitly authorizes that scope.
