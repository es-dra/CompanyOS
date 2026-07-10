# Runtime Surface Vector

Use this public-safe template when local, remote, server, process, or provider
state can drift apart.

```yaml
runtime_surface_vector:
  vector_id:
  project:
  local_repo:
    path:
    branch:
    head:
    upstream:
    dirty:
    stashes: []
  remote_repo:
    repo:
    default_branch:
    default_head:
    unexpected_branches: []
    open_prs: []
  runtime_surfaces:
    - label:
      location:
      branch:
      head:
      dirty:
      service:
      health:
  system_services: []
  listening_ports: []
  processes:
    - pid:
      cwd:
      command:
      port:
      expected: true | false
  provider_gates:
    llm:
    image:
    video:
    vision:
    asr:
    external_download:
  drift_findings: []
  allowed_next_actions: []
  blocked_actions: []
  non_claims: []
```
