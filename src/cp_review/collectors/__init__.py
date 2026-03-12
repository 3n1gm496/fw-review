"""Collectors and raw snapshot helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def save_raw_json(path: Path, payload: dict[str, Any]) -> None:
    """Persist a raw API response for troubleshooting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
