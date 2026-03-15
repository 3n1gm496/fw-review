from __future__ import annotations

import pytest
from pydantic import SecretStr

from cp_review.checkpoint_client import CheckPointClient
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.exceptions import ReadOnlyViolationError


def _build_settings() -> AppConfig:
    return AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
        ),
        collection=CollectionConfig(),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def test_call_api_blocks_mutating_command():
    client = CheckPointClient(_build_settings())
    try:
        with pytest.raises(ReadOnlyViolationError):
            client.call_api("set-access-rule", {"uid": "rule-1"})
    finally:
        client.close()


def test_call_api_allows_read_only_command_with_prefix():
    client = CheckPointClient(_build_settings())
    try:
        client._request = lambda command, payload, allow_unsafe=False: {"command": command, "payload": payload}  # type: ignore[method-assign]
        data = client.call_api("show-access-rulebase", {"name": "Network"})
        assert data["command"] == "show-access-rulebase"
        assert data["payload"]["name"] == "Network"
    finally:
        client.close()
