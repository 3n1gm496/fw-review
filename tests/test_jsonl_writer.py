from __future__ import annotations

import json
from pathlib import Path

from cp_review.reports.jsonl_writer import write_findings_jsonl


def test_write_findings_jsonl(tmp_path: Path):
    output = tmp_path / "findings.jsonl"
    write_findings_jsonl(
        output,
        [
            {"finding_type": "no_log_rules", "rule_uid": "r1"},
            {"finding_type": "unused_rules", "rule_uid": "r2"},
        ],
    )
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["rule_uid"] == "r1"
    assert json.loads(lines[1])["rule_uid"] == "r2"
