# fw-review Handoff

## Current State

- Release: `v0.3.0`
- Current shared SHA: `dcb0977`
- Main operator path: web cockpit
- Fallback operator path: `cp-review run`
- Quality baseline:
  - `make check` green
  - `make audit` green
  - coverage above 84%

## What Is Ready

- Read-only Check Point policy collection and normalization
- Semantic cleanup analysis and remediation queue
- Shared local-first remediation cockpit with:
  - users and RBAC
  - campaigns
  - review and approval workflow
  - audit trail
  - comments
  - run launch and sync
  - drift, health, executive, and run-detail views
- Release metadata, changelog, and versioning aligned to `v0.3.0`

## Standard Operator Commands

```bash
./scripts/bootstrap.sh
source .venv/bin/activate
cp-review web init --config config/settings.yaml
cp-review web serve --config config/settings.yaml
```

Then open:

```text
http://127.0.0.1:8765
```

## First Live Office Run

```bash
cp-review doctor --config config/settings.yaml --check-api
cp-review web init --config config/settings.yaml
cp-review web serve --config config/settings.yaml
```

If the API readiness check passes:

```bash
cp-review run --config config/settings.yaml
```

Or launch a run from the web cockpit as an `approver` or `admin`.

## Shared Cockpit Admin Tasks

Create a reviewer:

```bash
cp-review web create-user --config config/settings.yaml --username reviewer1 --role reviewer --password 'change-me'
```

Create a campaign:

```bash
cp-review web create-campaign --config config/settings.yaml --campaign-key q2-cleanup --name "Q2 Cleanup" --owner reviewer1
```

Rebuild the shared index safely:

```bash
cp-review web sync --config config/settings.yaml --rebuild
```

## Release / Quality Commands

```bash
make check
make audit
make sbom
make benchmark
```

## Key Files

- Product overview: `README.md`
- Release notes: `CHANGELOG.md`
- Release process: `RELEASE.md`
- Operations: `RUNBOOK.md`
- Enterprise roadmap: `ROADMAP.md`

## Known Residual Risks

- Real Check Point environments can still differ in payload shape, CA trust, permissions, and data volume.
- Some legacy analyzer modules remain in the tree with lower coverage, but the main semantic relationship path is validated.
- The shared cockpit is strong for local/internal use, but still assumes a trusted internal environment and local deployment model.

## Handoff Checklist

- Confirm credentials and CA bundle on the target host
- Run `cp-review doctor --check-api`
- Verify `make check` on the target environment if you changed dependencies
- Create named shared users instead of relying on the bootstrap admin
- Use campaigns for cleanup tracking rather than ad hoc queue work
- Tag future releases through `RELEASE.md`
