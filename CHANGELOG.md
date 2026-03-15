# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- Enterprise quality gates (`ruff`, `mypy`, `pytest-cov`) via Makefile and CI.
- Security workflows (CodeQL + dependency review).
- Governance docs: roadmap, contribution guide, and security policy.
- New tests for read-only API guardrails, config credential modes, CLI smoke paths, and collector contracts.
- Output compatibility policy and release process documentation.

### Changed
- `analyze` and `report` commands now support offline execution without management API credentials.

