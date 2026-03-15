# Contributing to fw-review

## Development Setup
1. Create and activate a virtual environment.
2. Install project dependencies:
   `pip install -e .[dev]`
3. Copy environment/config templates:
   `cp .env.example .env && cp config/settings.example.yaml config/settings.yaml`

## Local Quality Gates
- Run full local checks before opening a PR:
  `make check`
- For quick iteration:
  - `make test`
  - `make lint`
  - `make typecheck`

## Branch and PR Rules
- Use short-lived feature branches from `main`.
- Keep PRs scoped and include tests for behavior changes.
- Reference risk/impact on read-only guarantees for API interactions.
- Require passing CI before merge.

## Commit Style
- Use imperative, descriptive commit messages.
- Prefer conventional prefixes when possible:
  - `feat:`
  - `fix:`
  - `chore:`
  - `test:`
  - `docs:`

## Testing Expectations
- Unit tests required for new analyzers, config behavior, and API client guardrails.
- Regressions must include a failing test first, then the fix.
- Preserve fixture-based tests to avoid reliance on live firewall APIs in CI.
