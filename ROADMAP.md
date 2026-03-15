# fw-review Enterprise Roadmap

## Vision
`fw-review` evolves from a solid technical prototype into an enterprise-ready product with predictable delivery, security controls, and measurable quality.

## Current Baseline (March 2026)
- Core CLI workflow implemented: collect, analyze, report, full-run.
- Read-only API guardrails implemented in client code.
- Unit tests available for normalization, analysis, config loading, and collection.
- Missing enterprise controls: CI gates, static checks, security workflow, contribution standards, and explicit release hardening milestones.

## Target Operating Model
- Every change is validated by automated quality and security checks.
- Runtime behavior is deterministic and documented for operators.
- Security posture is continuously verified (SAST, dependency/update hygiene, vulnerability intake process).
- Release readiness is tracked through objective acceptance criteria.

## Delivery Phases

### Phase 1 - Foundation Hardening (Now)
- Introduce CI pipeline with lint, type check, tests, and coverage threshold.
- Add pre-commit hooks for local consistency.
- Add CONTRIBUTING and SECURITY policies.
- Add Makefile tasks to standardize developer workflows.
- Improve config/runtime ergonomics and add regression tests.

Status: Completed on March 16, 2026.

### Phase 2 - Product Reliability
- Add contract tests for Check Point API adapters with recorded fixtures.
- Add smoke tests for CLI command flows (`analyze`, `report`) on fixture datasets.
- Define backward compatibility policy for output schema (`dataset.json`, findings).
- Add changelog and semantic versioning workflow.

Status: In progress. First implementation delivered on March 16, 2026.

### Phase 3 - Enterprise Security & Compliance
- Add SBOM generation and artifact signing.
- Add dependency vulnerability scanning with policy thresholds.
- Add provenance metadata to release artifacts.
- Introduce mandatory security review checklist for feature changes.

Status: In progress. First implementation delivered on March 16, 2026.

### Phase 4 - Scale & Operations
- Add performance benchmarks for large rulebases.
- Add structured run metrics (duration, API calls, finding counts).
- Add optional integration with SIEM/data lake export formats.
- Publish operational runbook for incident and rollback procedures.

## Definition of Done for Enterprise Readiness (v1)
- CI required on pull requests with passing lint, type checks, tests, and coverage gate >= 60% (progressively raised toward 85%).
- Security workflow enabled (CodeQL + dependency review).
- Local developer setup reproducible via one standard command set.
- Documented contribution and vulnerability reporting process.
- No critical/high known defects in core collection/analyze/report flow.
