# cp-review

`cp-review` is a read-only CLI for reviewing Check Point on-premises Access Control policy on a Security Management Server in the R81.20 family. It uses the Management Web API directly over HTTPS, persists raw API snapshots locally, normalizes large rulebases into reviewable datasets, and produces technical findings in JSON, CSV, and HTML.

The current enterprise path is built around:

- a single operator entrypoint: `cp-review run`
- an actionable remediation queue
- semantic rule relationships instead of name-only heuristics
- static HTML artifacts suitable for technical review and cleanup campaigns
- policy health scoring and top-remediation shortlists
- local campaign workflow state and what-if simulation

## Safety model

- Read-only API usage only: `login`, `logout`, and `show`/`list`/`query` style calls.
- Mutating operations such as `set`, `add`, `delete`, `publish`, `discard`, and `install-policy` are blocked in code.
- TLS verification is enabled by default. Use `--ca-bundle` for internal CA trust and reserve `--insecure` for lab-only troubleshooting.
- Credentials are loaded from environment variables or a local `.env` file and are never written to output artifacts.

## Runtime

- Linux x86_64
- Python 3.11 or 3.12
- Intended for a jump host or Linux workstation with network reachability to the Check Point Management API

## Operator Quick Start

```bash
./scripts/bootstrap.sh
source .venv/bin/activate
cp-review web init --config config/settings.yaml
cp-review web serve --config config/settings.yaml
```

If you want to materialize config files manually instead of relying on `bootstrap.sh`, run:

```bash
cp-review init
cp-review web init --config config/settings.yaml
```

The web cockpit is now the standard operator path. It gives you:

- shared sign-in with persisted session state
- multi-user roles: `viewer`, `reviewer`, `approver`, `admin`
- overview and policy health
- remediation queue with live review state
- shared campaign board with owner/member tracking
- rule explainability and what-if simulation
- run launch and sync from the UI
- drift inspection and health checks

`cp-review run` remains the standard non-web operator fallback. It performs collection, analysis, queue generation, HTML reporting, and run validation in one command.

Update the environment variables named by the config file before the first live run:

```bash
export CP_MGMT_USERNAME="readonly_api_user"
export CP_MGMT_PASSWORD="replace_me"
```

## Advanced Commands

```bash
cp-review web init --config config/settings.yaml
cp-review web create-user --config config/settings.yaml --username reviewer1 --role reviewer --password 'change-me'
cp-review web create-campaign --config config/settings.yaml --campaign-key q2-cleanup --name "Q2 Cleanup" --owner reviewer1
cp-review web serve --config config/settings.yaml
cp-review web doctor --config config/settings.yaml
cp-review web sync --config config/settings.yaml
cp-review web export-state --config config/settings.yaml --format yaml
cp-review web export-tickets --config config/settings.yaml
cp-review collect --config config/settings.yaml
cp-review analyze --config config/settings.yaml
cp-review queue --config config/settings.yaml
cp-review explain --config config/settings.yaml --rule-uid <rule_uid>
cp-review simulate --config config/settings.yaml --rule-uid <rule_uid>
cp-review review-state --config config/settings.yaml --rule-uid <rule_uid> --owner netops --campaign q2-cleanup --status assigned
cp-review report --config config/settings.yaml
cp-review full-run --config config/settings.yaml
cp-review compare --config config/settings.yaml --summary-html
cp-review doctor --config config/settings.yaml --check-api
cp-review doctor --config config/settings.yaml --offline
cp-review validate-run --config config/settings.yaml
cp-review validate-run --config config/settings.yaml --strict
```

## Enterprise quality workflow

```bash
make bootstrap
make setup
make run
make web
make check
make sbom
make audit
make benchmark
```

- `make check` runs lint, type checks, and tests with coverage enforcement.
- `make sbom` generates a CycloneDX SBOM at `output/sbom.cdx.json`.
- `make audit` runs dependency vulnerability scanning and fails on findings.
- `make benchmark` runs a repeatable flattening benchmark for large-rulebase simulation.
- `make run` executes the operator wrapper against `config/settings.yaml`.
- `make web` launches the remediation cockpit on `127.0.0.1:8765`.
- CI workflows under `.github/workflows/` run the same checks on pull requests.
- See [`ROADMAP.md`](ROADMAP.md) for the enterprise hardening plan.

## Web Cockpit

The remediation cockpit is a local-first web app built around:

- Python server-rendered HTML
- SQLite for shared UI/workflow state, users, sessions, and campaigns
- filesystem artifacts as the source of truth for runs
- a shared multi-user model for jump hosts and Linux workstations

The default flow is:

```bash
cp-review web init --config config/settings.yaml
cp-review web create-user --config config/settings.yaml --username reviewer1 --role reviewer --password 'change-me'
cp-review web serve --config config/settings.yaml
```

Then open:

```text
http://127.0.0.1:8765
```

Public web commands:

- `cp-review web init`: create `config/web.yaml`, initialize SQLite, sync existing runs, and bootstrap a temporary admin if no users exist yet
- `cp-review web serve`: start the remediation cockpit
- `cp-review web doctor`: validate Python, config, CA bundle, templates, DB, and output path readiness
- `cp-review web sync`: import run artifacts into SQLite, with `--rebuild` support for full index reconstruction
- `cp-review web export-state`: export current review workflow state from SQLite to YAML/JSON
- `cp-review web export-tickets`: export ticket-ready remediation drafts with deep links back into the cockpit
- `cp-review web create-user`: create or rotate a shared cockpit user
- `cp-review web create-campaign`: create or update a shared remediation campaign

Main pages:

- `/`: overview, quick wins, latest run, policy health
- `/queue`: remediation queue with filters and workflow state
- `/campaigns`: shared campaign board with members and queue load
- `/executive`: KPI/trend surface for leadership and cleanup sponsors
- `/runs`: indexed run history and manifest-backed validation
- `/runs/<run_id>`: artifact and queue drill-down for one run
- `/rules/<rule_uid>`: explainability and related-rule context
- `/simulate/<rule_uid>`: what-if impact simulation
- `/drift`: two-run comparison and regression view
- `/settings`: core config, web config, and recent jobs
- `/health`: cockpit doctor checks

## Outputs

- `output/raw/<run_id>/`: raw API responses for rulebase pages, packages, objects, and targeted logs
- `output/normalized/<run_id>/dataset.json`: canonical normalized rule dataset
- `output/reports/<run_id>/findings.json`: analyzer findings
- `output/reports/<run_id>/findings.csv`: CSV export for technical review
- `output/reports/<run_id>/report.html`: HTML report
- `output/reports/<run_id>/review-queue.json`: canonical remediation queue
- `output/reports/<run_id>/review-queue.csv`: queue export for spreadsheets and ticket prep
- `output/reports/<run_id>/review-queue.html`: static queue view for reviewers
- `output/reports/<run_id>/review-state.yaml`: local review workflow state
- `output/reports/<run_id>/top-remediation.json`: top prioritized action buckets for cleanup campaigns
- `output/reports/<run_id>/policy-health.json`: overall, package, and layer health scores
- `output/reports/<run_id>/drift.json`: finding drift summary from `compare`
- `output/reports/<run_id>/drift-summary.html`: HTML drift summary from `compare --summary-html`
- `output/reports/<run_id>/drift.metrics.json`: drift command metrics
- `output/reports/<run_id>/drift.provenance.json`: drift command provenance
- `output/reports/<run_id>/run-manifest.json`: run completeness manifest for `collect`/`analyze`/`report`/`full-run`
- `output/web/fw-review-web.db`: SQLite index for runs, queue state, users, sessions, campaigns, and job activity
- `output/reports/<run_id>/ticket-drafts.json`: ticket-ready export generated from the current remediation shortlist
- `cp-review validate-run` verifies manifest integrity, artifact hashes, queue consistency, and summary counts
- `cp-review validate-run --strict` also fails on structural collection degradation such as `OBJECT_LOOKUP_FAILED`, `LOG_QUERY_FAILED`, and `NO_ACCESS_LAYERS`
- partial `show-object` and `show-logs` failures are preserved as structured warnings in the dataset and run manifest instead of being silently lost

## Review Model

The tool now produces two main outputs:

- `findings`: technical detections such as `exact_duplicate`, `semantic_duplicate`, `full_shadow`, `partial_shadow`, `conflicting_overlap`, `broad_rule_before_specific_rule`, `exception_rule_misordered`, and `merge_candidates`
- `review queue`: action-oriented items grouped into `REMOVE_CANDIDATE`, `RESTRICT_SCOPE`, `REORDER_CANDIDATE`, and `MERGE_CANDIDATE`

On top of that, the current operator workflow also includes:

- a `policy health` score per package and layer
- `top remediation actions` for fast cleanup campaign triage
- local `review-state` ownership and campaign metadata
- `simulate` output to estimate whether a rule looks covered before removal
- ticket-ready export drafts for downstream Jira/ServiceNow-style workflows

## What The Engine Checks

The current semantic engine goes beyond simple string comparison. It now uses:

- nested group expansion for referenced objects
- host and network containment
- service group expansion and normalized port ranges
- embedded `objects-dictionary` payloads when the API returns them
- install-on and application/site dimensions in rule relationships

Typical outcomes:

- `exact_duplicate`: same normalized signature in the same layer
- `semantic_duplicate`: same effective scope after normalization
- `full_shadow`: earlier rule covers the later rule on all relevant axes
- `partial_shadow`: earlier rule overlaps strongly but leaves residual differences on one or more axes
- `merge_candidates`: nearby rules differ on a single mergeable axis such as source, destination, or service
- `conflicting_overlap`: overlapping scope with different action, requiring policy-intent review

Broad-rule findings now also include an advisor that suggests:

- which axis to restrict first
- why that axis is the best first cleanup move
- a recommended remediation sequence

Conflict findings are also classified to make triage more useful, for example:

- `allow_then_deny_exception`
- `deny_then_allow_override`
- `same_scope_policy_conflict`

Each queue item includes:

- affected rule identity
- action type
- priority
- confidence
- related rules
- plain-language rationale
- residual differences when applicable
- conflict or merge strategy context when applicable
- recommended next step
- optional owner, campaign, and due date metadata from the local review workflow

## Recommended Office Flow

```bash
cp-review doctor --config config/settings.yaml --check-api
cp-review web init --config config/settings.yaml
cp-review web serve --config config/settings.yaml
cp-review compare --config config/settings.yaml --summary-html
```

Use `validate-run --strict` when you want the run to fail on structural degradation such as:

- partial object enrichment failures
- targeted log collection failures
- packages without access layers

## Current Enterprise Notes

- Git operations are expected to run over HTTPS with GitHub CLI-backed credentials, not SSH.
- The cockpit remains local-first in deployment style, but it now includes shared login, role-aware workflow, campaign state, executive KPIs, artifact viewing, rebuildable SQLite state, and ticket-draft export.

## Caveats

- Check Point response fields can vary across deployments and details levels. The project isolates uncertain schema handling in adapter helpers and preserves raw payloads for inspection.
- Inline-layer handling is conservative in v1. Unsupported nested structures are marked in the normalized dataset and surfaced as warnings/findings instead of being silently dropped.
- Targeted log queries rely on localized adapter assumptions and may need tuning against saved raw responses in a given environment.
- The current shared release uses local SQLite-backed auth and role checks; enterprise SSO remains the next natural step rather than a blocker for shared use.

## Governance

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Output compatibility policy: `OUTPUT_COMPATIBILITY.md`
- Release workflow: `RELEASE.md`
- Provenance metadata: `output/reports/<run_id>/provenance.json`
- Run manifest: `output/reports/<run_id>/run-manifest.json`
- `findings.json` is always written as the canonical pipeline artifact, even if `reporting.json_findings` is disabled, so `report`, `compare`, and recovery flows remain functional.
- Operational runbook: `RUNBOOK.md`
