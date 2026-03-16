"""Finding drift comparison helpers."""

from __future__ import annotations

from typing import Any


def finding_identity(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """Build a stable identity tuple for cross-run finding comparison."""
    return (
        str(finding.get("finding_type", "")),
        str(finding.get("rule_uid", "")),
        str(finding.get("package_name", "")),
        str(finding.get("layer_name", "")),
        str(finding.get("rule_number", "")),
    )


def compare_findings(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two finding sets and return drift summary."""
    previous_map = {finding_identity(item): item for item in previous}
    current_map = {finding_identity(item): item for item in current}

    new_ids = sorted(set(current_map) - set(previous_map))
    resolved_ids = sorted(set(previous_map) - set(current_map))
    persisting_ids = sorted(set(previous_map) & set(current_map))

    return {
        "previous_count": len(previous),
        "current_count": len(current),
        "new_count": len(new_ids),
        "resolved_count": len(resolved_ids),
        "persisting_count": len(persisting_ids),
        "new_findings": [current_map[item] for item in new_ids],
        "resolved_findings": [previous_map[item] for item in resolved_ids],
        "persisting_findings": [current_map[item] for item in persisting_ids],
    }
