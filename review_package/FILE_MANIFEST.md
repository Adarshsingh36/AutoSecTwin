# File Manifest

This review package intentionally contains only the files needed to understand the approval, execution, revalidation, and reporting path. It excludes the full project and all unrelated or secret-bearing materials.

## Included files

- README.md – package overview, scope, and interpretation guidance
- WORKFLOW_MAP.md – step-by-step approval and execution path
- AUDIT_FINDINGS.md – findings and evidence summary
- TEST_RESULTS.md – exact safe test command and result
- CONFIGURATION.md – relevant settings and defaults
- RELEVANT_SOURCE/
  - api/routes/approvals.py – approval request and decision endpoints
  - api/routes/orchestration.py – orchestration dispatch and job tracking
  - api/routes/remediation.py – manual execution and revalidation endpoints
  - api/schemas/autosectwin.py – approval/remediation request and response schemas
  - core/config.py – runtime configuration and safety defaults
  - database/models/approval.py – approval linkage model
  - database/models/remediation.py – remediation execution and verification state model
  - database/migrations/versions/c3e5b8a1d9f2_remediation_approval_twin_linkage.py – schema for approval-remediation-twin linkage
  - services/approval/workflow.py – request_approval and decide logic
  - services/orchestration/closed_loop_orchestrator.py – orchestration stopping point at approval gate
  - services/remediation/patch_executor.py – executor preconditions and approval matching
  - services/remediation/pipeline.py – execute + revalidate lifecycle
  - services/remediation/tasks.py – background dispatch logic
  - services/remediation/handlers/docker_patch_handler.py – destroy + provision replacement twin flow
  - services/revalidation/revalidation_engine.py – independent revalidation engine
  - services/reporting/closed_loop_report_service.py – report assembly from the remediation chain
  - services/reporting/report_generator.py – closed-loop report content
  - services/twin_provisioning_service.py – twin creation, health checks, and destroy behavior
  - tests/unit/test_approval_workflow.py – approval workflow guard tests
  - tests/unit/test_patch_executor.py – executor safety tests
  - tests/integration/test_remediation_approval_schema.py – linkage/schema regression tests

## Exclusions and warnings

The following items were intentionally excluded:

- .env and .env.* files
- credentials, API tokens, private keys, certificates, and secrets
- database dumps and database URLs with embedded passwords
- Exploit-DB items, exploit payload collections, large exploit files, and binary content
- virtual environments, dependency directories, node_modules, Python caches, and unrelated generated files
- the full repository or any unrelated application modules

Potentially sensitive content omitted or not safely classified:

- live production configuration values, including any environment-provided secrets or connection strings
- real deployment-specific settings and live infrastructure state

This package is intentionally conservative: it focuses on the workflow logic and evidence that can be shared safely without exposing credentials or live system details.
