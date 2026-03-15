# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- Placeholder for upcoming changes.

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
