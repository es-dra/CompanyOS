# GFR Startup Contract

GFR compiles a task into an executable startup packet.

Minimum fields:

- identity: role, task class, and responsibility;
- context pack: smallest required read set;
- write scope: allowed files, directories, or repositories;
- non-goals: explicit exclusions;
- gates: provider, network, external download, and destructive-operation gates;
- evidence route: verification commands and artifact paths;
- feedback route: whether this task can produce a reusable feedback packet.

Default principle:

```text
compile before execution
scope before write
evidence before claim
feedback before rule promotion
```
