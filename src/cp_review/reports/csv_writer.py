"""CSV findings writer."""

from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cp_review.models import FindingRecord

FIELDS = [
    "finding_type",
    "severity",
    "risk_score",
    "cleanup_confidence",
    "package_name",
    "layer_name",
    "rule_number",
    "rule_uid",
    "rule_name",
    "recommended_action",
    "review_note",
    "evidence",
]


def write_findings_csv(path: Path, findings: Sequence[FindingRecord | dict[str, Any]]) -> Path:
    """Write findings to CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for item in findings:
            row: dict[str, Any] = item.model_dump(mode="json") if isinstance(item, FindingRecord) else dict(item)
            row["evidence"] = json.dumps(row.get("evidence", {}), sort_keys=True, default=str)
            writer.writerow({field: row.get(field, "") for field in FIELDS})
    return path
