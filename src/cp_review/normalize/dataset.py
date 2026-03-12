"""Dataset persistence helpers."""

from __future__ import annotations

import json
from pathlib import Path

from cp_review.models import NormalizedDataset


def save_dataset(path: Path, dataset: NormalizedDataset) -> Path:
    """Persist a normalized dataset as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataset.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_dataset(path: Path) -> NormalizedDataset:
    """Load a normalized dataset from JSON."""
    return NormalizedDataset.model_validate_json(path.read_text(encoding="utf-8"))
