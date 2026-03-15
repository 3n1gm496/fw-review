from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from cp_review.collectors.access_rulebase import _layer_selector, collect_access_rulebase_pages
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig, RunPaths
from cp_review.exceptions import CollectionError


class PagingClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, int | str]] = []

    def call_api(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        assert command == "show-access-rulebase"
        offset = int(payload["offset"])  # type: ignore[arg-type]
        limit = int(payload["limit"])  # type: ignore[arg-type]
        self.calls.append({"command": command, "offset": offset, "limit": limit})

        pages = {
            0: {"total": 3, "rulebase": [{"uid": "r1"}, {"uid": "r2"}]},
            2: {"total": 3, "rulebase": [{"uid": "r3"}]},
        }
        return pages[offset]


def _settings(tmp_path: Path) -> AppConfig:
    return AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
        ),
        collection=CollectionConfig(page_limit=2, save_raw=False, output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def _run_paths(tmp_path: Path) -> RunPaths:
    base = tmp_path / "output"
    return RunPaths(
        run_id="test-run",
        base_output=base,
        raw_dir=base / "raw" / "test-run",
        normalized_dir=base / "normalized" / "test-run",
        reports_dir=base / "reports" / "test-run",
    )


def test_collect_access_rulebase_pages_paginates_on_offset(tmp_path: Path):
    settings = _settings(tmp_path)
    run_paths = _run_paths(tmp_path)
    client = PagingClient()

    pages = collect_access_rulebase_pages(
        client=client,
        settings=settings,
        run_paths=run_paths,
        package_name="Standard",
        layer={"name": "Network"},
    )

    assert len(pages) == 2
    assert client.calls == [
        {"command": "show-access-rulebase", "offset": 0, "limit": 2},
        {"command": "show-access-rulebase", "offset": 2, "limit": 2},
    ]


def test_layer_selector_requires_uid_or_name():
    with pytest.raises(CollectionError):
        _layer_selector({"type": "access-layer"})
