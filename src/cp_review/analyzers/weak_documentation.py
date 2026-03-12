"""Documentation-quality analyzer."""

from __future__ import annotations

import re

from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding

USELESS_NAME = re.compile(r"^(rule[ _-]*\d+|cleanup|new rule)$", re.IGNORECASE)


def run(rules: list[RuleRecord]) -> list[FindingRecord]:
    """Flag missing or weak rule names/comments."""
    findings: list[FindingRecord] = []
    for rule in rules:
        weak_name = not rule.rule_name.strip() or bool(USELESS_NAME.match(rule.rule_name.strip()))
        weak_comment = not rule.comments.strip() or rule.comments.strip().lower() in {"n/a", "none", "todo"}
        if not weak_name and not weak_comment:
            continue
        findings.append(
            make_finding(
                rule,
                finding_type="weak_documentation",
                severity="low",
                evidence={"rule_name": rule.rule_name, "comments": rule.comments},
                recommended_action="ADD_COMMENT_OR_RENAME_RULE",
                review_note="Rules should have a descriptive name and meaningful technical review comment.",
            )
        )
    return findings
