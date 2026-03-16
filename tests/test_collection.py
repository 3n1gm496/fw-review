from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.collectors.packages import collect_policy_snapshot
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig, RunPaths
from cp_review.exceptions import CheckPointApiError


class FakeClient:
    def __init__(self, fixture):
        self.fixture = fixture

    def call_api(self, command, payload):
        if command == "show-package":
            return {
                "name": "Standard",
                "access-layers": [{"name": "Network", "type": "access-layer"}],
            }
        if command == "show-access-rulebase":
            return self.fixture
        if command == "show-object":
            return {"uid": payload["uid"], "name": payload["uid"], "type": "generic-object"}
        raise AssertionError(f"Unexpected command: {command}")


def test_collect_policy_snapshot_writes_raw_and_builds_dataset(tmp_path):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_rulebase_page.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    settings = AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
        ),
        collection=CollectionConfig(package="Standard", output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )
    run_paths = RunPaths(
        run_id="test-run",
        base_output=tmp_path / "output",
        raw_dir=tmp_path / "output" / "raw" / "test-run",
        normalized_dir=tmp_path / "output" / "normalized" / "test-run",
        reports_dir=tmp_path / "output" / "reports" / "test-run",
    )
    run_paths.raw_dir.mkdir(parents=True)
    run_paths.normalized_dir.mkdir(parents=True)
    run_paths.reports_dir.mkdir(parents=True)

    dataset = collect_policy_snapshot(FakeClient(fixture), settings, run_paths)

    assert len(dataset.rules) == 4
    assert (run_paths.raw_dir / "packages" / "Standard.json").exists()
    raw_rulebase_files = list((run_paths.raw_dir / "rulebase").glob("*.json"))
    assert raw_rulebase_files


def test_collect_policy_snapshot_records_object_lookup_warnings(tmp_path):
    fixture = {
        "rulebase": [
            {
                "type": "access-rule",
                "uid": "rule-1",
                "rule-number": 1,
                "name": "Rule 1",
                "enabled": True,
                "action": {"name": "Accept"},
                "source": [{"uid": "obj-missing", "name": "obj-missing"}],
                "destination": [{"name": "Any", "type": "CpmiAnyObject"}],
                "service": [{"name": "Any", "type": "service-any"}],
                "track": {"name": "Log"},
                "comments": "",
            }
        ],
        "total": 1,
    }

    class DegradedClient(FakeClient):
        def call_api(self, command, payload):
            if command == "show-object":
                raise CheckPointApiError("object lookup failed")
            return super().call_api(command, payload)

    settings = AppConfig(
        management=ManagementConfig(host="mgmt.example.local", username=SecretStr("user"), password=SecretStr("pass")),
        collection=CollectionConfig(package="Standard", output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )
    run_paths = RunPaths(
        run_id="test-run",
        base_output=tmp_path / "output",
        raw_dir=tmp_path / "output" / "raw" / "test-run",
        normalized_dir=tmp_path / "output" / "normalized" / "test-run",
        reports_dir=tmp_path / "output" / "reports" / "test-run",
    )
    run_paths.raw_dir.mkdir(parents=True)
    run_paths.normalized_dir.mkdir(parents=True)
    run_paths.reports_dir.mkdir(parents=True)

    dataset = collect_policy_snapshot(DegradedClient(fixture), settings, run_paths)

    assert len(dataset.rules) == 1
    assert any(warning.code == "OBJECT_LOOKUP_FAILED" and warning.object_uid == "obj-missing" for warning in dataset.warnings)


def test_collect_policy_snapshot_discovers_multiple_packages_and_mixed_layer_shapes(tmp_path):
    fixture = {
        "rulebase": [
            {
                "type": "access-rule",
                "uid": "rule-1",
                "rule-number": 1,
                "name": "Rule 1",
                "enabled": True,
                "action": {"name": "Accept"},
                "source": [{"uid": "src-1", "name": "src-1"}],
                "destination": [{"uid": "dst-1", "name": "dst-1"}],
                "service": [{"uid": "svc-1", "name": "svc-1"}],
                "track": {"name": "Log"},
                "comments": "",
            }
        ],
        "total": 1,
    }

    class MultiPackageClient:
        def __init__(self):
            self.show_packages_calls = 0

        def call_api(self, command, payload):
            if command == "show-packages":
                self.show_packages_calls += 1
                if payload["offset"] == 0:
                    return {
                        "packages": [
                            {"name": "Standard", "access-layers": [{"name": "Network", "type": "access-layer"}]},
                            {"name": "Remote", "access-layers": ["Remote-Layer"]},
                        ],
                        "total": 3,
                    }
                return {
                    "packages": [
                        {"name": "BrokenPackage", "access-layers": []},
                    ],
                    "total": 3,
                }
            if command == "show-access-rulebase":
                return fixture
            if command == "show-object":
                return {"uid": payload["uid"], "name": f"resolved-{payload['uid']}", "type": "host"}
            raise AssertionError(f"Unexpected command: {command}")

    settings = AppConfig(
        management=ManagementConfig(host="mgmt.example.local", username=SecretStr("user"), password=SecretStr("pass")),
        collection=CollectionConfig(output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )
    run_paths = RunPaths(
        run_id="test-run",
        base_output=tmp_path / "output",
        raw_dir=tmp_path / "output" / "raw" / "test-run",
        normalized_dir=tmp_path / "output" / "normalized" / "test-run",
        reports_dir=tmp_path / "output" / "reports" / "test-run",
    )
    run_paths.raw_dir.mkdir(parents=True)
    run_paths.normalized_dir.mkdir(parents=True)
    run_paths.reports_dir.mkdir(parents=True)

    dataset = collect_policy_snapshot(MultiPackageClient(), settings, run_paths)

    assert dataset.packages == ["Standard", "Remote", "BrokenPackage"]
    assert len(dataset.rules) == 2
    assert {rule.package_name for rule in dataset.rules} == {"Standard", "Remote"}
    assert any(warning.code == "NO_ACCESS_LAYERS" and warning.package_name == "BrokenPackage" for warning in dataset.warnings)
    assert dataset.rules[0].source[0].name.startswith("resolved-")


def test_collect_policy_snapshot_tolerates_incomplete_object_payloads(tmp_path):
    fixture = {
        "rulebase": [
            {
                "type": "access-rule",
                "uid": "rule-1",
                "rule-number": 1,
                "name": "Rule 1",
                "enabled": True,
                "action": {"name": "Accept"},
                "source": [{"uid": "obj-incomplete", "name": "obj-incomplete"}],
                "destination": [{"uid": "dst-1", "name": "dst-1"}],
                "service": [{"uid": "svc-1", "name": "svc-1"}],
                "track": {"name": "Log"},
                "comments": "",
            }
        ],
        "total": 1,
    }

    class IncompleteObjectClient(FakeClient):
        def call_api(self, command, payload):
            if command == "show-object":
                return {"uid": payload["uid"]}
            return super().call_api(command, payload)

    settings = AppConfig(
        management=ManagementConfig(host="mgmt.example.local", username=SecretStr("user"), password=SecretStr("pass")),
        collection=CollectionConfig(package="Standard", output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )
    run_paths = RunPaths(
        run_id="test-run",
        base_output=tmp_path / "output",
        raw_dir=tmp_path / "output" / "raw" / "test-run",
        normalized_dir=tmp_path / "output" / "normalized" / "test-run",
        reports_dir=tmp_path / "output" / "reports" / "test-run",
    )
    run_paths.raw_dir.mkdir(parents=True)
    run_paths.normalized_dir.mkdir(parents=True)
    run_paths.reports_dir.mkdir(parents=True)

    dataset = collect_policy_snapshot(IncompleteObjectClient(fixture), settings, run_paths)

    assert len(dataset.rules) == 1
    assert dataset.rules[0].source[0].name == "obj-incomplete"
    assert dataset.rules[0].source[0].type is None
