# Operations Runbook

## Scope
This runbook covers production-style operation of `cp-review` runs and incident handling for collection/analyze/report pipelines.

## Standard Execution
1. Validate environment:
   - credentials available for API-backed commands (`collect`, `full-run`)
   - config file reviewed (`config/settings.yaml`)
2. Run quality checks on current branch:
   - `make check`
3. Execute job:
   - `cp-review full-run --config config/settings.yaml`
4. Validate outputs:
   - `output/normalized/<run_id>/dataset.json`
   - `output/reports/<run_id>/findings.json`
   - `output/reports/<run_id>/metrics.json`
   - `output/reports/<run_id>/provenance.json`

## Incident Triage

### Symptom: API command failures
- Check `output/raw/<run_id>/` snapshots and structured logs.
- Verify TLS configuration (`ca_bundle` vs `insecure`).
- Confirm credentials and API user role are still valid/read-only.

### Symptom: Unexpected output regression
- Compare `dataset.json` and `findings.json` against previous successful run.
- Verify compatibility expectations in `OUTPUT_COMPATIBILITY.md`.
- Check recent changelog entries and commit diffs.

### Symptom: Performance degradation
- Run `make benchmark`.
- Compare benchmark output with previous baselines.
- Inspect API call volume in `metrics.json`.

## Rollback Procedure
1. Identify last known-good commit/tag.
2. Deploy/checkout that revision.
3. Re-run `make check`.
4. Execute `cp-review full-run` with the same config and compare outputs.
5. Keep failed run artifacts for post-mortem.

## Post-Incident Actions
- Open corrective PR with root-cause summary.
- Add/extend tests to cover the failure mode.
- Update `CHANGELOG.md` and this runbook if process gaps were found.
