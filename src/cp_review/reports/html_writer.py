"""HTML report writer."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cp_review.models import FindingRecord, NormalizedDataset, ReviewQueueItem


def _normalize_findings(findings: Sequence[FindingRecord | dict[str, Any]]) -> list[FindingRecord]:
    return [item if isinstance(item, FindingRecord) else FindingRecord.model_validate(item) for item in findings]


def write_html_report(
    path: Path,
    *,
    findings: Sequence[FindingRecord | dict[str, Any]],
    dataset: NormalizedDataset,
    settings: Any,
    review_queue: list[ReviewQueueItem] | None = None,
) -> Path:
    """Render the technical HTML report."""
    normalized_findings = _normalize_findings(findings)
    review_queue = review_queue or []
    by_type = Counter(item.finding_type for item in normalized_findings)
    by_severity = Counter(item.severity for item in normalized_findings)
    by_action = Counter(item.action_type for item in review_queue)
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.policies["json.dumps_function"] = lambda value, **kwargs: json.dumps(value, default=str, **kwargs)
    template = env.get_template("report.html.j2")
    html = template.render(
        generated_at=datetime.now(UTC),
        dataset=dataset,
        findings=normalized_findings,
        by_type=dict(by_type),
        by_severity=dict(by_severity),
        by_action=dict(by_action),
        review_queue=review_queue,
        config_summary=settings.sanitized_summary(),
        top_risk=sorted(normalized_findings, key=lambda item: item.risk_score, reverse=True)[:10],
        top_cleanup=sorted(normalized_findings, key=lambda item: item.cleanup_confidence, reverse=True)[:10],
        top_reorder=[item for item in review_queue if item.action_type == "REORDER_CANDIDATE"][:10],
        top_merge=[item for item in review_queue if item.action_type == "MERGE_CANDIDATE"][:10],
        top_restrict=[item for item in review_queue if item.action_type == "RESTRICT_SCOPE"][:10],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
