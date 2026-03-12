"""Logging helpers."""

from __future__ import annotations

import json
import logging


class StructuredFormatter(logging.Formatter):
    """Render log records as readable structured lines."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a record with optional structured payload."""
        base = super().format(record)
        event_data = getattr(record, "event_data", None)
        if not event_data:
            return base
        serialized = json.dumps(event_data, default=str, sort_keys=True)
        return f"{base} event={serialized}"


def configure_logging(level: int = logging.INFO) -> None:
    """Configure process-wide logging."""
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(level)
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        StructuredFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    root.setLevel(level)
    root.addHandler(handler)
