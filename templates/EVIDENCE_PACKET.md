# Evidence Packet

Use this public-safe template to close a claim, route integration, or request
evaluation.

```yaml
evidence_packet:
  evidence_id:
  goal_id:
  task_id:
  claim:
  evidence_state: structure_verification | runtime_verification | provider_smoke | human_acceptance | business_validation | durable_memory_promotion | active_rule_promotion
  artifacts: []
  commands_or_checks:
    - command:
      result: pass | fail | not_run
      notes:
  runtime_surfaces_checked: []
  evaluator_verdict: not_required | pending | pass | fail | pass_with_residual_risk | blocked_with_decision
  non_claims: []
  residual_risks: []
  next_required_evidence:
  integration_queue_state: none | review_pending | evaluator_pending | push_pr_pending | ci_pending | ci_failed | merge_pending | deploy_pending | deploy_dir_updated | service_restart_required | runtime_check_pending | runtime_stale | delete_pending | retire_pending | defer_with_owner | superseded | delivered
  improvement_route: no_feedback_needed | project_record_only | improvement_candidate | limited_trial | delete_rule | rewrite_rule | merge_rule | human_review_required
```
