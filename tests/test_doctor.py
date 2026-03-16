from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr

from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.doctor import run_local_readiness_checks


def _settings(tmp_path: Path, *, ca_bundle: str | None = None) -> AppConfig:
    return AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
            ca_bundle=ca_bundle,
        ),
        collection=CollectionConfig(output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def test_doctor_local_checks_ok_without_ca_bundle(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    result = run_local_readiness_checks(_settings(tmp_path))
    assert result["summary"] == "ok"
    statuses = {item["name"]: item["status"] for item in result["checks"]}
    assert statuses["output_dir_writable"] == "ok"
    assert statuses["credentials_env"] == "ok"


def test_doctor_local_checks_fail_when_missing_ca_bundle(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    result = run_local_readiness_checks(_settings(tmp_path, ca_bundle=str(tmp_path / "missing-ca.pem")))
    assert result["summary"] == "fail"
    statuses = {item["name"]: item["status"] for item in result["checks"]}
    assert statuses["ca_bundle_path"] == "fail"


def test_doctor_local_checks_fail_when_credentials_missing_by_default(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    result = run_local_readiness_checks(_settings(tmp_path))
    assert result["summary"] == "fail"
    statuses = {item["name"]: item["status"] for item in result["checks"]}
    assert statuses["credentials_env"] == "fail"


def test_doctor_local_checks_warn_when_credentials_missing_offline(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    result = run_local_readiness_checks(_settings(tmp_path), require_credentials=False)
    statuses = {item["name"]: item["status"] for item in result["checks"]}
    assert statuses["credentials_env"] == "warn"
