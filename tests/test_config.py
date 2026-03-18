from __future__ import annotations

import pytest

from cp_review.config import latest_file, load_settings
from cp_review.exceptions import ConfigurationError


def test_load_settings_resolves_env_and_review_rule_overrides(tmp_path, monkeypatch):
    review_rules = tmp_path / "review_rules.yaml"
    review_rules.write_text(
        "analysis:\n  low_hit_threshold: 9\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        """
management:
  host: https://mgmt.example.local/
  username_env: CP_MGMT_USERNAME
  password_env: CP_MGMT_PASSWORD
collection:
  output_dir: ./output
analysis:
  review_rules_path: ./review_rules.yaml
reporting:
  html_report: true
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")

    settings = load_settings(config_path)

    assert settings.management.host == "mgmt.example.local"
    assert settings.analysis.low_hit_threshold == 9
    assert settings.management.username.get_secret_value() == "user"
    assert settings.collection.output_dir == tmp_path / "output"


def test_load_settings_allows_missing_credentials_for_offline_commands(tmp_path, monkeypatch):
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        """
management:
  host: https://mgmt.example.local/
collection:
  output_dir: ./output
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)

    settings = load_settings(config_path, require_credentials=False)

    assert settings.management.username is None
    assert settings.management.password is None


def test_load_settings_requires_credentials_by_default(tmp_path, monkeypatch):
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        """
management:
  host: mgmt.example.local
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)

    with pytest.raises(ConfigurationError):
        load_settings(config_path)


def test_latest_file_prefers_timestamped_run_directory_over_mtime_skew(tmp_path):
    normalized_dir = tmp_path / "normalized"
    older_run = normalized_dir / "20260315T120000Z"
    newer_run = normalized_dir / "20260316T120000Z"
    older_run.mkdir(parents=True)
    newer_run.mkdir(parents=True)
    older_file = older_run / "dataset.json"
    newer_file = newer_run / "dataset.json"
    older_file.write_text("{}", encoding="utf-8")
    newer_file.write_text("{}", encoding="utf-8")
    older_file.touch()
    newer_file.touch()
    older_file.touch()

    assert latest_file(normalized_dir, "*/dataset.json") == newer_file


def test_load_settings_resolves_review_rules_relative_to_repo_root(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    review_rules = config_dir / "review_rules.yaml"
    review_rules.write_text(
        "analysis:\n  low_hit_threshold: 11\n",
        encoding="utf-8",
    )
    config_path = config_dir / "settings.yaml"
    config_path.write_text(
        """
management:
  host: mgmt.example.local
analysis:
  review_rules_path: ./config/review_rules.yaml
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")

    settings = load_settings(config_path)

    assert settings.analysis.review_rules_path == review_rules.resolve()
    assert settings.analysis.low_hit_threshold == 11
