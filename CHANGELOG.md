# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.3.0] - 2026-03-18

### Added
- Local-first remediation cockpit with `cp-review web init`, `serve`, `doctor`, `sync`, and state export flows.
- Shared multi-user backend with persisted sessions, roles, campaigns, comments, audit trail, and executive surface.
- Review queue workflow with approval state, owner/campaign tracking, ticket draft export, and policy health summaries.
- Stronger semantic cleanup engine outputs and workflow UX around run detail, campaigns, drift, settings, and health pages.

### Changed
- The web cockpit is now the primary operator workflow, with `cp-review run` retained as the non-web fallback path.
- Queue, rule detail, run detail, campaign board, executive, settings, drift, and health pages now favor operational summaries over raw JSON dumps.
- Review and approval responsibilities are now separated more clearly in both RBAC and UI behavior.

### Fixed
- Prevented duplicate audit entries on repeated workflow submits with unchanged state.
- Deduplicated repeated rule comments caused by fast double submits.
- Hardened rebuild/sync behavior so shared workflow state is backed up and restored explicitly.
- Improved expired-session handling for both browser navigation and API requests.
- Added clearer recovery behavior for missing artifacts and degraded run context.

## [0.2.0] - 2026-03-16

### Added
- Enterprise quality gates (`ruff`, `mypy`, `pytest-cov`) via Makefile and CI.
- Security workflows (CodeQL + dependency review).
- Governance docs: roadmap, contribution guide, and security policy.
- New tests for read-only API guardrails, config credential modes, CLI smoke paths, and collector contracts.
- Output compatibility policy and release process documentation.
- Supply-chain workflow with CycloneDX SBOM generation and build provenance attestation.
- Dependency vulnerability scanning (`pip-audit`) with blocking policy in CI.
- PR security checklist template for mandatory review controls.
- Run-level provenance metadata output (`provenance.json`) for CLI commands.
- Structured run metrics output (`metrics.json`) with duration and API/finding counters.
- JSONL export option for SIEM/data-lake ingestion (`siem_jsonl`).
- Flattening benchmark script and `make benchmark` workflow for performance tracking.
- Operational runbook for triage and rollback procedures.

### Changed
- `analyze` and `report` commands now support offline execution without management API credentials.
