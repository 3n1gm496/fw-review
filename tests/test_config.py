from __future__ import annotations

from cp_review.config import load_settings


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
