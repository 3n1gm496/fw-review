# Release Process

## Versioning
- Follow Semantic Versioning (`MAJOR.MINOR.PATCH`).
- Decide bump type using `OUTPUT_COMPATIBILITY.md`.

## Release Checklist
1. Ensure `make check` passes.
2. Update `CHANGELOG.md` under a new version section.
3. Bump `version` in `pyproject.toml`.
4. Commit release metadata:
   `chore(release): vX.Y.Z`
5. Tag:
   `git tag vX.Y.Z`
6. Push branch and tag:
   `git push origin <branch> --follow-tags`

## Post-release
- Verify CI and security workflows passed on tagged commit.
- Publish release notes from changelog highlights.
