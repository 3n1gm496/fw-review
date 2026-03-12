"""JSON findings writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cp_review.models import FindingRecord


def write_findings_json(path: Path, findings: list[FindingRecord | dict[str, Any]]) -> Path:
    """Write findings to JSON."""
    payload = [item.model_dump(mode="json") if isinstance(item, FindingRecord) else item for item in findings]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
