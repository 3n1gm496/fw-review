"""Targeted local log evidence collection."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from cp_review.collectors import save_raw_json
from cp_review.config import AppConfig, RunPaths
from cp_review.exceptions import CheckPointApiError
from cp_review.models import LogEvidence

LOGGER = logging.getLogger(__name__)


def _build_log_payload(rule_uid: str, days: int) -> dict[str, Any]:
    """Build a conservative log query payload for a rule UID."""
    return {
        "query": f'rule:"{rule_uid}"',
        "limit": 10,
        "time-frame": f"last-{days}-days",
    }


def collect_logs_for_rule_uids(
    client: Any,
    settings: AppConfig,
    run_paths: RunPaths,
    rule_uids: list[str],
) -> dict[str, LogEvidence]:
    """Collect targeted log evidence for shortlisted rule UIDs."""
    evidence: dict[str, LogEvidence] = {}
    for rule_uid in rule_uids:
        payload = _build_log_payload(rule_uid, settings.collection.log_days)
        try:
            response = client.call_api("show-logs", payload)
        except CheckPointApiError as exc:
            LOGGER.warning(
                "Targeted log collection failed",
                extra={"event_data": {"rule_uid": rule_uid, "error": str(exc)}},
            )
            continue
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "logs" / f"{rule_uid}.json", response)
        logs = response.get("logs") or response.get("records") or response.get("data") or []
        evidence[rule_uid] = LogEvidence(
            query=payload["query"],
            count=response.get("logs-count") or response.get("total") or len(logs),
            sample_logs=list(logs)[:5],
            collected_at=datetime.now(UTC),
        )
    return evidence
