# Output Compatibility Policy

## Scope
This policy covers:
- `output/normalized/<run_id>/dataset.json`
- `output/reports/<run_id>/findings.json`
- `output/reports/<run_id>/findings.csv`

## Compatibility Levels
- Patch release (`x.y.Z`): bug fixes only, no breaking field changes.
- Minor release (`x.Y.z`): additive changes only (new optional fields).
- Major release (`X.y.z`): breaking schema changes allowed with migration notes.

## Rules
- Existing keys must not be removed in minor/patch releases.
- Existing key types must not change in minor/patch releases.
- New keys must be optional and safe to ignore.
- Finding `finding_type` values are treated as stable identifiers once released.

## Change Control
- Any schema-impacting PR must:
  - include fixture updates
  - include parser/consumer compatibility notes
  - update `CHANGELOG.md`
