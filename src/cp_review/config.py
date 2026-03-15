"""Configuration loading and runtime path helpers."""

from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator

from cp_review.exceptions import ConfigurationError


def _merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two dictionaries."""
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


class ManagementConfig(BaseModel):
    """Connection settings for the Management Web API."""

    host: str
    username_env: str = "CP_MGMT_USERNAME"
    password_env: str = "CP_MGMT_PASSWORD"
    ca_bundle: str | None = None
    insecure: bool = False
    timeout_seconds: int = 60
    max_retries: int = 4
    username: SecretStr | None = Field(default=None, exclude=True)
    password: SecretStr | None = Field(default=None, exclude=True)

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        """Remove protocol suffixes from host input."""
        return value.replace("https://", "").rstrip("/")


class CollectionConfig(BaseModel):
    """Collection tuning settings."""

    package: str | None = None
    page_limit: int = 200
    save_raw: bool = True
    collect_hitcount: bool = True
    collect_logs_for_shortlist: bool = True
    log_days: int = 90
    shortlist_log_limit: int = 50
    output_dir: Path = Path("./output")

    @field_validator("page_limit")
    @classmethod
    def validate_page_limit(cls, value: int) -> int:
        """Keep page size within a reasonable range."""
        if value <= 0 or value > 500:
            raise ValueError("page_limit must be between 1 and 500")
        return value


class AnalysisConfig(BaseModel):
    """Analyzer thresholds and feature flags."""

    zero_hit_days: int = 90
    low_hit_threshold: int = 5
    broad_group_size_threshold: int = 50
    enable_duplicate_candidates: bool = True
    enable_shadow_candidates: bool = True
    review_rules_path: Path | None = None


class ReportingConfig(BaseModel):
    """Report output controls."""

    html_report: bool = True
    csv_findings: bool = True
    json_findings: bool = True


class AppConfig(BaseModel):
    """Top-level configuration."""

    management: ManagementConfig
    collection: CollectionConfig = Field(default_factory=CollectionConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    def sanitized_summary(self) -> dict[str, Any]:
        """Return a serializable config summary without secrets."""
        return self.model_dump(
            exclude={"management": {"username", "password"}},
            mode="json",
        )


@dataclass(frozen=True)
class RunPaths:
    """Filesystem locations for a collection/report run."""

    run_id: str
    base_output: Path
    raw_dir: Path
    normalized_dir: Path
    reports_dir: Path


def load_settings(
    config_path: Path,
    *,
    env_file: Path | None = None,
    overrides: dict[str, Any] | None = None,
    require_credentials: bool = True,
) -> AppConfig:
    """Load application settings from YAML, review overrides, env, and CLI overrides."""
    config_dir = config_path.parent.resolve()
    repo_root = config_dir.parent.resolve() if config_dir.name == "config" else config_dir
    if env_file:
        load_dotenv(env_file, override=False)
    else:
        default_env = repo_root / ".env"
        if default_env.exists():
            load_dotenv(default_env, override=False)

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            raw_data = yaml.safe_load(handle) or {}
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Config file not found: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in config file: {config_path}") from exc

    analysis_raw = raw_data.get("analysis", {}) if isinstance(raw_data.get("analysis"), dict) else {}
    review_path_value = analysis_raw.get("review_rules_path")
    if review_path_value:
        review_path = Path(review_path_value)
        if not review_path.is_absolute():
            review_path = (config_dir / review_path).resolve()
        if review_path.exists():
            with review_path.open("r", encoding="utf-8") as handle:
                review_data = yaml.safe_load(handle) or {}
            raw_data = _merge_dicts(raw_data, review_data)

    if overrides:
        raw_data = _merge_dicts(raw_data, overrides)

    try:
        settings = AppConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc

    username = os.getenv(settings.management.username_env)
    password = os.getenv(settings.management.password_env)
    if require_credentials:
        if not username or not password:
            raise ConfigurationError(
                "Management API credentials are missing. "
                f"Set {settings.management.username_env} and {settings.management.password_env}."
            )
        settings.management.username = SecretStr(username)
        settings.management.password = SecretStr(password)
    else:
        if username:
            settings.management.username = SecretStr(username)
        if password:
            settings.management.password = SecretStr(password)
    if not settings.collection.output_dir.is_absolute():
        settings.collection.output_dir = (repo_root / settings.collection.output_dir).resolve()
    if settings.analysis.review_rules_path and not settings.analysis.review_rules_path.is_absolute():
        settings.analysis.review_rules_path = (config_dir / settings.analysis.review_rules_path).resolve()
    return settings


def apply_cli_overrides(
    *,
    ca_bundle: str | None = None,
    insecure: bool | None = None,
    package: str | None = None,
) -> dict[str, Any]:
    """Convert CLI options into nested config overrides."""
    overrides: dict[str, Any] = {}
    if ca_bundle is not None or insecure is not None:
        overrides["management"] = {}
    if ca_bundle is not None:
        overrides["management"]["ca_bundle"] = ca_bundle
    if insecure is not None:
        overrides["management"]["insecure"] = insecure
    if package is not None:
        overrides.setdefault("collection", {})
        overrides["collection"]["package"] = package
    return overrides


def build_run_paths(output_dir: Path, run_id: str | None = None) -> RunPaths:
    """Create timestamped output paths for a run."""
    run_id = run_id or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base_output = output_dir.resolve()
    raw_dir = base_output / "raw" / run_id
    normalized_dir = base_output / "normalized" / run_id
    reports_dir = base_output / "reports" / run_id
    for path in (raw_dir, normalized_dir, reports_dir):
        path.mkdir(parents=True, exist_ok=True)
    return RunPaths(
        run_id=run_id,
        base_output=base_output,
        raw_dir=raw_dir,
        normalized_dir=normalized_dir,
        reports_dir=reports_dir,
    )


def latest_file(directory: Path, pattern: str) -> Path:
    """Return the most recently modified file matching a glob pattern."""
    matches = list(directory.glob(pattern))
    if not matches:
        raise ConfigurationError(f"No files matching {pattern!r} found in {directory}")
    return max(matches, key=lambda path: path.stat().st_mtime)
