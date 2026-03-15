# cp-review

`cp-review` is a read-only CLI for reviewing Check Point on-premises Access Control policy on a Security Management Server in the R81.20 family. It uses the Management Web API directly over HTTPS, persists raw API snapshots locally, normalizes large rulebases into reviewable datasets, and produces technical findings in JSON, CSV, and HTML.

## Safety model

- Read-only API usage only: `login`, `logout`, and `show`/`list`/`query` style calls.
- Mutating operations such as `set`, `add`, `delete`, `publish`, `discard`, and `install-policy` are blocked in code.
- TLS verification is enabled by default. Use `--ca-bundle` for internal CA trust and reserve `--insecure` for lab-only troubleshooting.
- Credentials are loaded from environment variables or a local `.env` file and are never written to output artifacts.

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
cp config/settings.example.yaml config/settings.yaml
```

Set the environment variables named by the config file:

```bash
export CP_MGMT_USERNAME="readonly_api_user"
export CP_MGMT_PASSWORD="replace_me"
```

## Commands

```bash
cp-review collect --config config/settings.yaml
cp-review analyze --config config/settings.yaml
cp-review report --config config/settings.yaml
cp-review full-run --config config/settings.yaml
```

## Enterprise quality workflow

```bash
make setup
make check
make sbom
make audit
```

- `make check` runs lint, type checks, and tests with coverage enforcement.
- `make sbom` generates a CycloneDX SBOM at `output/sbom.cdx.json`.
- `make audit` runs dependency vulnerability scanning and fails on findings.
- CI workflows under `.github/workflows/` run the same checks on pull requests.
- See [`ROADMAP.md`](ROADMAP.md) for the enterprise hardening plan.

## Outputs

- `output/raw/<run_id>/`: raw API responses for rulebase pages, packages, objects, and targeted logs
- `output/normalized/<run_id>/dataset.json`: canonical normalized rule dataset
- `output/reports/<run_id>/findings.json`: analyzer findings
- `output/reports/<run_id>/findings.csv`: CSV export for technical review
- `output/reports/<run_id>/report.html`: HTML report

## Caveats

- Check Point response fields can vary across deployments and details levels. The project isolates uncertain schema handling in adapter helpers and preserves raw payloads for inspection.
- Inline-layer handling is conservative in v1. Unsupported nested structures are marked in the normalized dataset and surfaced as warnings/findings instead of being silently dropped.
- Targeted log queries rely on localized adapter assumptions and may need tuning against saved raw responses in a given environment.

## Governance

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Output compatibility policy: `OUTPUT_COMPATIBILITY.md`
- Release workflow: `RELEASE.md`
- Provenance metadata: `output/reports/<run_id>/provenance.json`
