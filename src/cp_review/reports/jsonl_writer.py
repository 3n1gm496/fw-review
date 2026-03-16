"""JSONL findings writer for SIEM/Data-lake ingestion."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cp_review.models import FindingRecord


def write_findings_jsonl(path: Path, findings: Sequence[FindingRecord | dict[str, Any]]) -> Path:
    """Write one finding per line for downstream stream ingestion."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in findings:
            payload = item.model_dump(mode="json") if isinstance(item, FindingRecord) else dict(item)
            handle.write(json.dumps(payload, sort_keys=True))
            handle.write("\n")
    return path
