"""Typer CLI for cp-review."""

from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import Any

import typer

from cp_review.analyzers import analyze_dataset
from cp_review.checkpoint_client import CheckPointClient
from cp_review.collectors.logs import collect_logs_for_rule_uids
from cp_review.collectors.packages import collect_policy_snapshot
from cp_review.compare import compare_findings
from cp_review.config import apply_cli_overrides, build_run_paths, latest_file, load_settings
from cp_review.doctor import run_local_readiness_checks
from cp_review.exceptions import CpReviewError
from cp_review.logging_conf import configure_logging
from cp_review.models import FindingRecord
from cp_review.normalize.dataset import load_dataset, save_dataset
from cp_review.provenance import write_provenance_file
from cp_review.reports.compare_html_writer import write_compare_summary_html
from cp_review.reports.csv_writer import write_findings_csv
from cp_review.reports.html_writer import write_html_report
from cp_review.reports.json_writer import write_findings_json
from cp_review.reports.jsonl_writer import write_findings_jsonl
from cp_review.review_queue import (
    build_review_queue,
    load_review_state,
    review_queue_summary,
    write_review_queue_csv,
    write_review_queue_html,
    write_review_queue_json,
    write_review_state,
)
from cp_review.run_manifest import write_run_manifest
from cp_review.run_metrics import build_run_metrics, write_run_metrics
from cp_review.validate_run import validate_run_manifest

app = typer.Typer(add_completion=False, no_args_is_help=True)
LOGGER = logging.getLogger(__name__)
DEFAULT_SETTINGS_TEMPLATE = """management:
  host: "mgmt.example.local"
  username_env: "CP_MGMT_USERNAME"
  password_env: "CP_MGMT_PASSWORD"
  ca_bundle: "/opt/certs/internal_ca.pem"
  insecure: false
  timeout_seconds: 60
  max_retries: 4

collection:
  package: "STANDARD_OR_SELECTED_PACKAGE"
  page_limit: 200
  save_raw: true
  collect_hitcount: true
  collect_logs_for_shortlist: true
  log_days: 90
  shortlist_log_limit: 50
  output_dir: "./output"

analysis:
  zero_hit_days: 90
  low_hit_threshold: 5
  broad_group_size_threshold: 50
  enable_duplicate_candidates: true
  enable_shadow_candidates: true
  review_rules_path: "./config/review_rules.yaml"

reporting:
  html_report: true
  csv_findings: true
  json_findings: true
  siem_jsonl: false
  siem_jsonl_filename: "findings.jsonl"
"""
DEFAULT_REVIEW_RULES_TEMPLATE = """analysis:
  zero_hit_days: 90
  low_hit_threshold: 5
  broad_group_size_threshold: 50
  enable_duplicate_candidates: true
  enable_shadow_candidates: true

notes:
  - "Use this file to tune analyzer thresholds without changing code."
  - "Fields are merged into the analysis section of the main settings file."
"""
DEFAULT_ENV_TEMPLATE = 'CP_MGMT_USERNAME="readonly_api_user"\nCP_MGMT_PASSWORD="replace_me"\n'
STRICT_WARNING_CODES = {"OBJECT_LOOKUP_FAILED", "LOG_QUERY_FAILED", "NO_ACCESS_LAYERS"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _template_text(relative_path: str, fallback: str) -> str:
    candidate = _repo_root() / relative_path
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")
    return fallback


def _load_config(
    config: Path,
    env_file: Path | None,
    ca_bundle: str | None,
    insecure: bool | None,
    package: str | None,
    *,
    require_credentials: bool = True,
):
    overrides = apply_cli_overrides(ca_bundle=ca_bundle, insecure=insecure, package=package)
    return load_settings(config, env_file=env_file, overrides=overrides, require_credentials=require_credentials)


def _normalize_findings(findings: list[FindingRecord | dict[str, Any]]) -> list[FindingRecord]:
    return [item if isinstance(item, FindingRecord) else FindingRecord.model_validate(item) for item in findings]


def _write_findings_bundle(findings: list[FindingRecord], reports_dir: Path, settings) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    findings_json = reports_dir / "findings.json"
    findings_csv = reports_dir / "findings.csv"
    findings_jsonl = reports_dir / settings.reporting.siem_jsonl_filename

    write_findings_json(findings_json, findings)
    artifacts["findings_json"] = findings_json
    if settings.reporting.csv_findings:
        write_findings_csv(findings_csv, findings)
        artifacts["findings_csv"] = findings_csv
    if settings.reporting.siem_jsonl:
        write_findings_jsonl(findings_jsonl, findings)
        artifacts["siem_jsonl"] = findings_jsonl
    return artifacts


def _write_provenance(
    settings,
    reports_dir: Path,
    command: str,
    run_id: str,
    artifacts: dict[str, Path],
    *,
    filename: str = "provenance.json",
) -> Path:
    return write_provenance_file(
        reports_dir / filename,
        command=command,
        run_id=run_id,
        settings=settings,
        artifacts=artifacts,
    )


def _collect_shortlist_rule_uids(findings: list[FindingRecord], limit: int) -> list[str]:
    shortlist: list[str] = []
    interesting_types = {"unused_rules", "broad_allow", "no_log_rules", "high_risk_broad_usage", "conflicting_overlap"}
    for finding in sorted(findings, key=lambda item: (item.risk_score, item.cleanup_confidence), reverse=True):
        if finding.finding_type not in interesting_types:
            continue
        if finding.rule_uid not in shortlist:
            shortlist.append(finding.rule_uid)
        if len(shortlist) >= limit:
            break
    return shortlist


def _load_findings_file(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise CpReviewError(f"Findings file does not contain a list: {path}")
    return [dict(item) for item in payload if isinstance(item, dict)]


def _latest_two_findings_files(reports_root: Path) -> tuple[Path, Path]:
    matches = sorted(
        reports_root.glob("*/findings.json"),
        key=lambda item: (item.parent.name, item.stat().st_mtime),
    )
    if len(matches) < 2:
        raise CpReviewError(f"Need at least two findings files in {reports_root} to run compare")
    return matches[-2], matches[-1]


def _latest_run_manifest(reports_root: Path) -> Path:
    matches = sorted(reports_root.glob("*/run-manifest.json"), key=lambda item: (item.parent.name, item.stat().st_mtime))
    if not matches:
        raise CpReviewError(f"No run manifests found in {reports_root}")
    return matches[-1]


def _latest_dataset_path(output_dir: Path) -> Path:
    return latest_file(output_dir / "normalized", "*/dataset.json")


def _load_findings_for_report(
    dataset,
    findings_path: Path | None,
    settings,
    reports_dir: Path,
) -> tuple[list[FindingRecord], Path]:
    if findings_path is not None:
        findings = _normalize_findings(json.loads(findings_path.read_text(encoding="utf-8")))
        return findings, findings_path

    canonical_findings = reports_dir / "findings.json"
    if canonical_findings.exists():
        findings = _normalize_findings(json.loads(canonical_findings.read_text(encoding="utf-8")))
        return findings, canonical_findings

    findings = analyze_dataset(dataset, settings.analysis)
    write_findings_json(canonical_findings, findings)
    return findings, canonical_findings


def _write_review_queue_bundle(run_id: str, findings: list[FindingRecord], reports_dir: Path) -> tuple[list, dict[str, Path]]:
    existing_state = load_review_state(reports_dir / "review-state.yaml")
    queue_items = build_review_queue(findings, run_id=run_id, review_state=existing_state)
    artifacts = {
        "review_queue_json": write_review_queue_json(reports_dir / "review-queue.json", queue_items),
        "review_queue_csv": write_review_queue_csv(reports_dir / "review-queue.csv", queue_items),
        "review_queue_html": write_review_queue_html(reports_dir / "review-queue.html", queue_items),
        "review_state_yaml": write_review_state(reports_dir / "review-state.yaml", queue_items, existing_state),
    }
    return queue_items, artifacts


def _write_report_bundle(
    dataset,
    findings: list[FindingRecord],
    reports_dir: Path,
    settings,
    *,
    review_queue: list | None = None,
) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    if settings.reporting.html_report:
        report_html = reports_dir / "report.html"
        write_html_report(report_html, findings=findings, dataset=dataset, settings=settings, review_queue=review_queue or [])
        artifacts["report_html"] = report_html
    return artifacts


def _summary_with_queue(
    dataset,
    findings: list[FindingRecord],
    queue_items: list,
    *,
    extra: dict[str, Any] | None = None,
    phase_timings: dict[str, float] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "findings_count": len(findings),
        "review_queue_count": len(queue_items),
        "rules_count": len(dataset.rules),
        "warnings_count": len(dataset.warnings),
        "action_counts": review_queue_summary(queue_items)["action_counts"],
        "package_counts": dict(sorted(Counter(rule.package_name for rule in dataset.rules).items())),
        "layer_counts": dict(sorted(Counter(f"{rule.package_name}/{rule.layer_name}" for rule in dataset.rules).items())),
    }
    if phase_timings:
        summary["phase_timings_seconds"] = {key: round(value, 3) for key, value in sorted(phase_timings.items())}
    if extra:
        summary.update(extra)
    return summary


def _emit_manifest(
    *,
    reports_dir: Path,
    command: str,
    run_id: str,
    settings,
    artifacts: dict[str, Path],
    dataset,
    findings: list[FindingRecord],
    queue_items: list,
    summary: dict[str, Any],
) -> Path:
    provenance_path = _write_provenance(
        settings,
        reports_dir,
        command,
        run_id,
        artifacts={name: path for name, path in artifacts.items() if name != "provenance_json"},
    )
    manifest_artifacts = dict(artifacts)
    manifest_artifacts["provenance_json"] = provenance_path
    write_run_manifest(
        reports_dir / "run-manifest.json",
        command=command,
        run_id=run_id,
        settings=settings,
        artifacts=manifest_artifacts,
        summary=summary,
        warnings=dataset.warnings,
    )
    return provenance_path


def _build_init_report(target_dir: Path, settings_path: Path, env_path: Path, review_rules_path: Path) -> dict[str, Any]:
    checks = [
        {"name": "python_version", "status": "ok" if sys.version_info >= (3, 11) else "fail", "details": sys.version.split()[0]},
        {"name": "target_dir", "status": "ok", "details": str(target_dir)},
        {"name": "settings_yaml", "status": "ok" if settings_path.exists() else "fail", "details": str(settings_path)},
        {"name": "env_file", "status": "ok" if env_path.exists() else "fail", "details": str(env_path)},
        {"name": "review_rules_yaml", "status": "ok" if review_rules_path.exists() else "fail", "details": str(review_rules_path)},
    ]
    return {"summary": "fail" if any(item["status"] == "fail" for item in checks) else "ok", "checks": checks}


def _write_file_if_allowed(path: Path, content: str, *, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return
    path.write_text(content, encoding="utf-8")


def _explain_rule(
    dataset,
    findings: list[FindingRecord],
    queue_items: list,
    *,
    rule_uid: str,
) -> dict[str, Any]:
    matching_rule = next((rule for rule in dataset.rules if rule.rule_uid == rule_uid), None)
    if matching_rule is None:
        raise CpReviewError(f"Rule UID not found in dataset: {rule_uid}")
    related_findings = [item for item in findings if item.rule_uid == rule_uid]
    related_queue = [item for item in queue_items if item.rule_uid == rule_uid]
    related_rule_uids = sorted(
        {
            related_rule
            for item in related_findings
            for related_rule in item.evidence.get("related_rule_uids", [])
            if related_rule != rule_uid
        }
    )
    return {
        "rule": matching_rule.model_dump(mode="json"),
        "findings": [item.model_dump(mode="json") for item in related_findings],
        "queue_items": [item.model_dump(mode="json") for item in related_queue],
        "related_rules": related_rule_uids,
        "summary": {
            "finding_count": len(related_findings),
            "queue_item_count": len(related_queue),
        },
    }


def _execute_full_run(
    settings,
    *,
    generate_queue: bool = True,
    generate_report: bool | None = None,
) -> dict[str, Any]:
    run_paths = build_run_paths(settings.collection.output_dir)
    phase_timings: dict[str, float] = {}

    collect_started = perf_counter()
    with CheckPointClient(settings) as client:
        dataset = collect_policy_snapshot(client, settings, run_paths)
        dataset_path = save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
        phase_timings["collect"] = perf_counter() - collect_started

        analyze_started = perf_counter()
        findings = analyze_dataset(dataset, settings.analysis)
        if settings.collection.collect_logs_for_shortlist:
            shortlist = _collect_shortlist_rule_uids(findings, settings.collection.shortlist_log_limit)
            if shortlist:
                log_evidence, log_warnings = collect_logs_for_rule_uids(client, settings, run_paths, shortlist)
                dataset.log_evidence.update(log_evidence)
                dataset.warnings.extend(log_warnings)
                save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
                findings = analyze_dataset(dataset, settings.analysis)
        api_call_count = client.api_call_count
        api_commands = dict(client.command_counts)
        phase_timings["analyze"] = perf_counter() - analyze_started

    findings_artifacts = _write_findings_bundle(findings, run_paths.reports_dir, settings)
    queue_items: list = []
    queue_artifacts: dict[str, Path] = {}
    if generate_queue:
        queue_items, queue_artifacts = _write_review_queue_bundle(dataset.run_id, findings, run_paths.reports_dir)

    report_started = perf_counter()
    report_artifacts: dict[str, Path] = {}
    if generate_report if generate_report is not None else settings.reporting.html_report:
        report_artifacts = _write_report_bundle(dataset, findings, run_paths.reports_dir, settings, review_queue=queue_items)
    phase_timings["report"] = perf_counter() - report_started

    all_artifacts = {
        "dataset_json": dataset_path,
        **findings_artifacts,
        **queue_artifacts,
        **report_artifacts,
    }
    return {
        "dataset": dataset,
        "dataset_path": dataset_path,
        "findings": findings,
        "queue_items": queue_items,
        "api_call_count": api_call_count,
        "api_commands": api_commands,
        "phase_timings": phase_timings,
        "run_paths": run_paths,
        "artifacts": all_artifacts,
    }


@app.command()
def init(
    target_dir: Path = typer.Option(Path("."), "--target-dir", file_okay=False, help="Target project directory."),
    profile: str = typer.Option("office", "--profile", help="Bootstrap profile to materialize."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing bootstrap files."),
) -> None:
    """Create a ready-to-run local configuration for office usage."""
    configure_logging()
    if profile != "office":
        raise CpReviewError(f"Unsupported init profile: {profile}")

    target_dir = target_dir.resolve()
    settings_path = target_dir / "config" / "settings.yaml"
    review_rules_path = target_dir / "config" / "review_rules.yaml"
    env_path = target_dir / ".env"
    _write_file_if_allowed(settings_path, _template_text("config/settings.example.yaml", DEFAULT_SETTINGS_TEMPLATE), force=force)
    _write_file_if_allowed(
        review_rules_path,
        _template_text("config/review_rules.example.yaml", DEFAULT_REVIEW_RULES_TEMPLATE),
        force=force,
    )
    _write_file_if_allowed(env_path, _template_text(".env.example", DEFAULT_ENV_TEMPLATE), force=force)
    report = _build_init_report(target_dir, settings_path, env_path, review_rules_path)
    typer.echo(json.dumps(report, indent=2, sort_keys=True))
    if report["summary"] == "fail":
        raise typer.Exit(code=1)


@app.command()
def collect(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
    ca_bundle: str | None = typer.Option(None, "--ca-bundle", help="Override CA bundle path."),
    insecure: bool | None = typer.Option(None, "--insecure/--secure", help="Lab-only TLS override."),
    package: str | None = typer.Option(None, "--package", help="Collect only the selected package."),
) -> None:
    """Collect raw policy data and write a normalized dataset."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, ca_bundle, insecure, package)
    run_paths = build_run_paths(settings.collection.output_dir)
    with CheckPointClient(settings) as client:
        dataset = collect_policy_snapshot(client, settings, run_paths)
        api_call_count = client.api_call_count
        api_commands = dict(client.command_counts)
    dataset_path = save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
    metrics_path = write_run_metrics(
        run_paths.reports_dir / "metrics.json",
        build_run_metrics(
            command="collect",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            api_call_count=api_call_count,
            api_commands=api_commands,
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    summary = {
        "api_call_count": api_call_count,
        "rules_count": len(dataset.rules),
        "warnings_count": len(dataset.warnings),
        "phase_timings_seconds": {"collect": round(perf_counter() - started_at, 3)},
    }
    _emit_manifest(
        reports_dir=run_paths.reports_dir,
        command="collect",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={"dataset_json": dataset_path, "metrics_json": metrics_path},
        dataset=dataset,
        findings=[],
        queue_items=[],
        summary=summary,
    )
    typer.echo(f"Collected dataset: {dataset_path}")


@app.command()
def analyze(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    dataset_path: Path | None = typer.Option(None, "--dataset-path", dir_okay=False, help="Normalized dataset JSON."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Analyze a normalized dataset and emit findings plus remediation queue."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = _latest_dataset_path(settings.collection.output_dir)
    dataset = load_dataset(dataset_path)
    findings = analyze_dataset(dataset, settings.analysis)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    findings_artifacts = _write_findings_bundle(findings, reports_dir, settings)
    queue_items, queue_artifacts = _write_review_queue_bundle(dataset.run_id, findings, reports_dir)
    report_artifacts = _write_report_bundle(dataset, findings, reports_dir, settings, review_queue=queue_items)
    metrics_path = write_run_metrics(
        reports_dir / "metrics.json",
        build_run_metrics(
            command="analyze",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            findings_count=len(findings),
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    summary = _summary_with_queue(
        dataset,
        findings,
        queue_items,
        phase_timings={"analyze": perf_counter() - started_at},
    )
    _emit_manifest(
        reports_dir=reports_dir,
        command="analyze",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={"dataset_json": dataset_path, "metrics_json": metrics_path, **findings_artifacts, **queue_artifacts, **report_artifacts},
        dataset=dataset,
        findings=findings,
        queue_items=queue_items,
        summary=summary,
    )
    typer.echo(f"Findings written: {findings_artifacts['findings_json']}")


@app.command()
def queue(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    run_id: str | None = typer.Option(None, "--run-id", help="Specific run ID to materialize queue for."),
    dataset_path: Path | None = typer.Option(None, "--dataset-path", dir_okay=False, help="Normalized dataset JSON."),
    findings_path: Path | None = typer.Option(None, "--findings-path", dir_okay=False, help="Findings JSON."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Generate remediation queue artifacts from findings."""
    configure_logging()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = (
            settings.collection.output_dir / "normalized" / run_id / "dataset.json"
            if run_id
            else _latest_dataset_path(settings.collection.output_dir)
        )
    dataset = load_dataset(dataset_path)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    findings, findings_path = _load_findings_for_report(dataset, findings_path, settings, reports_dir)
    _write_findings_bundle(findings, reports_dir, settings)
    queue_items, artifacts = _write_review_queue_bundle(dataset.run_id, findings, reports_dir)
    typer.echo(
        json.dumps(
            {
                "summary": "ok",
                "run_id": dataset.run_id,
                "queue_items": len(queue_items),
                "artifacts": {key: str(path) for key, path in artifacts.items()},
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command()
def explain(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    rule_uid: str = typer.Option(..., "--rule-uid", help="Rule UID to explain."),
    run_id: str | None = typer.Option(None, "--run-id", help="Specific run ID to inspect."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Explain why one rule is in scope for remediation."""
    configure_logging()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    dataset_path = (
        settings.collection.output_dir / "normalized" / run_id / "dataset.json"
        if run_id
        else _latest_dataset_path(settings.collection.output_dir)
    )
    dataset = load_dataset(dataset_path)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    findings, _ = _load_findings_for_report(dataset, None, settings, reports_dir)
    queue_items, _ = _write_review_queue_bundle(dataset.run_id, findings, reports_dir)
    typer.echo(json.dumps(_explain_rule(dataset, findings, queue_items, rule_uid=rule_uid), indent=2, sort_keys=True))


@app.command()
def report(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    dataset_path: Path | None = typer.Option(None, "--dataset-path", dir_okay=False, help="Normalized dataset JSON."),
    findings_path: Path | None = typer.Option(None, "--findings-path", dir_okay=False, help="Findings JSON."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Generate the HTML report from a dataset, findings, and remediation queue."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = _latest_dataset_path(settings.collection.output_dir)
    dataset = load_dataset(dataset_path)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    findings, findings_path = _load_findings_for_report(dataset, findings_path, settings, reports_dir)
    findings_artifacts = _write_findings_bundle(findings, reports_dir, settings)
    queue_items, queue_artifacts = _write_review_queue_bundle(dataset.run_id, findings, reports_dir)
    report_artifacts = _write_report_bundle(dataset, findings, reports_dir, settings, review_queue=queue_items)
    metrics_path = write_run_metrics(
        reports_dir / "metrics.json",
        build_run_metrics(
            command="report",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            findings_count=len(findings),
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    summary = _summary_with_queue(
        dataset,
        findings,
        queue_items,
        phase_timings={"report": perf_counter() - started_at},
    )
    _emit_manifest(
        reports_dir=reports_dir,
        command="report",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "metrics_json": metrics_path,
            **findings_artifacts,
            **queue_artifacts,
            **report_artifacts,
        },
        dataset=dataset,
        findings=findings,
        queue_items=queue_items,
        summary=summary,
    )
    typer.echo(f"Report written: {report_artifacts.get('report_html', reports_dir / 'report.html')}")


@app.command("full-run")
def full_run(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
    ca_bundle: str | None = typer.Option(None, "--ca-bundle", help="Override CA bundle path."),
    insecure: bool | None = typer.Option(None, "--insecure/--secure", help="Lab-only TLS override."),
    package: str | None = typer.Option(None, "--package", help="Collect only the selected package."),
) -> None:
    """Run collection, analysis, reporting, and queue generation in sequence."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, ca_bundle, insecure, package)
    result = _execute_full_run(settings)
    dataset = result["dataset"]
    metrics_path = write_run_metrics(
        result["run_paths"].reports_dir / "metrics.json",
        build_run_metrics(
            command="full-run",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            api_call_count=result["api_call_count"],
            api_commands=result["api_commands"],
            findings_count=len(result["findings"]),
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    summary = _summary_with_queue(
        dataset,
        result["findings"],
        result["queue_items"],
        extra={"api_call_count": result["api_call_count"]},
        phase_timings=result["phase_timings"],
    )
    _emit_manifest(
        reports_dir=result["run_paths"].reports_dir,
        command="full-run",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={**result["artifacts"], "metrics_json": metrics_path},
        dataset=dataset,
        findings=result["findings"],
        queue_items=result["queue_items"],
        summary=summary,
    )
    typer.echo(f"Full run completed: {result['dataset_path']}")


@app.command()
def run(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
    ca_bundle: str | None = typer.Option(None, "--ca-bundle", help="Override CA bundle path."),
    insecure: bool | None = typer.Option(None, "--insecure/--secure", help="Lab-only TLS override."),
    package: str | None = typer.Option(None, "--package", help="Collect only the selected package."),
    strict_validate: bool = typer.Option(True, "--strict-validate/--no-strict-validate", help="Validate run in strict mode."),
) -> None:
    """Operator-friendly wrapper for the end-to-end enterprise path."""
    configure_logging()
    settings = _load_config(config, env_file, ca_bundle, insecure, package)
    result = _execute_full_run(settings)
    dataset = result["dataset"]
    total_started = perf_counter()
    metrics_path = write_run_metrics(
        result["run_paths"].reports_dir / "metrics.json",
        build_run_metrics(
            command="full-run",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=round(sum(result["phase_timings"].values()), 3),
            api_call_count=result["api_call_count"],
            api_commands=result["api_commands"],
            findings_count=len(result["findings"]),
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    summary = _summary_with_queue(
        dataset,
        result["findings"],
        result["queue_items"],
        extra={"api_call_count": result["api_call_count"]},
        phase_timings=result["phase_timings"],
    )
    _emit_manifest(
        reports_dir=result["run_paths"].reports_dir,
        command="full-run",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={**result["artifacts"], "metrics_json": metrics_path},
        dataset=dataset,
        findings=result["findings"],
        queue_items=result["queue_items"],
        summary=summary,
    )
    validate_report = validate_run_manifest(result["run_paths"].reports_dir / "run-manifest.json", strict=strict_validate)
    typer.echo(
        json.dumps(
            {
                "summary": validate_report["summary"],
                "run_id": dataset.run_id,
                "report_html": str(result["run_paths"].reports_dir / "report.html"),
                "review_queue_html": str(result["run_paths"].reports_dir / "review-queue.html"),
                "validation": validate_report,
                "duration_seconds": round(perf_counter() - total_started + sum(result["phase_timings"].values()), 3),
            },
            indent=2,
            sort_keys=True,
        )
    )
    if validate_report["summary"] == "fail":
        raise typer.Exit(code=1)


@app.command()
def compare(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    previous_findings: Path | None = typer.Option(None, "--previous-findings", dir_okay=False, help="Older findings JSON."),
    current_findings: Path | None = typer.Option(None, "--current-findings", dir_okay=False, help="Newer findings JSON."),
    output_path: Path | None = typer.Option(None, "--output-path", dir_okay=False, help="Drift output JSON path."),
    summary_html: bool = typer.Option(False, "--summary-html", help="Also render an HTML drift summary."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Compare two findings sets and generate a drift report."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)

    if previous_findings is None or current_findings is None:
        auto_previous, auto_current = _latest_two_findings_files(settings.collection.output_dir / "reports")
        previous_findings = previous_findings or auto_previous
        current_findings = current_findings or auto_current

    previous = _load_findings_file(previous_findings)
    current = _load_findings_file(current_findings)
    drift = compare_findings(previous, current)

    current_run_id = current_findings.parent.name
    reports_dir = settings.collection.output_dir / "reports" / current_run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_path or reports_dir / "drift.json"
    output_path.write_text(json.dumps(drift, indent=2, sort_keys=True), encoding="utf-8")

    drift_html_path: Path | None = None
    if summary_html:
        drift_html_path = write_compare_summary_html(reports_dir / "drift-summary.html", drift)

    metrics_path = write_run_metrics(
        reports_dir / "drift.metrics.json",
        build_run_metrics(
            command="compare",
            run_id=current_run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            findings_count=drift["current_count"],
        ),
    )
    provenance_path = _write_provenance(
        settings,
        reports_dir,
        "compare",
        current_run_id,
        artifacts={
            "previous_findings_json": previous_findings,
            "current_findings_json": current_findings,
            "drift_json": output_path,
            "metrics_json": metrics_path,
            **({"drift_summary_html": drift_html_path} if drift_html_path else {}),
        },
        filename="drift.provenance.json",
    )
    write_run_manifest(
        reports_dir / "drift.run-manifest.json",
        command="compare",
        run_id=current_run_id,
        settings=settings,
        artifacts={
            "previous_findings_json": previous_findings,
            "current_findings_json": current_findings,
            "drift_json": output_path,
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
            **({"drift_summary_html": drift_html_path} if drift_html_path else {}),
        },
        summary={
            "current_count": drift["current_count"],
            "new_count": drift["new_count"],
            "persisting_count": drift["persisting_count"],
            "resolved_count": drift["resolved_count"],
        },
    )
    typer.echo(f"Drift report written: {output_path}")


@app.command()
def doctor(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
    check_api: bool = typer.Option(False, "--check-api", help="Also validate API login and a read-only call."),
    offline: bool = typer.Option(False, "--offline", help="Allow missing API credentials for offline-only usage."),
    ca_bundle: str | None = typer.Option(None, "--ca-bundle", help="Override CA bundle path."),
    insecure: bool | None = typer.Option(None, "--insecure/--secure", help="Lab-only TLS override."),
) -> None:
    """Run readiness checks before office/prod execution."""
    configure_logging()
    settings = _load_config(
        config,
        env_file,
        ca_bundle,
        insecure,
        package=None,
        require_credentials=check_api,
    )

    report = run_local_readiness_checks(settings, require_credentials=not offline)
    checks = list(report["checks"])

    if check_api:
        try:
            with CheckPointClient(settings) as client:
                client.call_api("show-packages", {"limit": 1, "offset": 0, "details-level": "standard"})
            checks.append({"name": "api_login_readonly_call", "status": "ok", "details": "login/logout/show-packages succeeded"})
        except Exception as exc:  # noqa: BLE001
            checks.append({"name": "api_login_readonly_call", "status": "fail", "details": str(exc)})

    has_fail = any(item["status"] == "fail" for item in checks)
    typer.echo(json.dumps({"summary": "fail" if has_fail else "ok", "checks": checks}, indent=2, sort_keys=True))
    if has_fail:
        raise typer.Exit(code=1)


@app.command("validate-run")
def validate_run(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    run_id: str | None = typer.Option(None, "--run-id", help="Specific run ID to validate."),
    manifest_path: Path | None = typer.Option(None, "--manifest-path", dir_okay=False, help="Explicit run manifest path."),
    strict: bool = typer.Option(False, "--strict", help="Fail on missing queue/report artifacts and structural warnings."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Validate a completed run manifest and its artifacts."""
    configure_logging()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)

    if manifest_path is None:
        reports_root = settings.collection.output_dir / "reports"
        manifest_path = reports_root / run_id / "run-manifest.json" if run_id else _latest_run_manifest(reports_root)

    report = validate_run_manifest(manifest_path, strict=strict)
    typer.echo(json.dumps(report, indent=2, sort_keys=True))
    if report["summary"] == "fail":
        raise typer.Exit(code=1)


def main() -> None:
    """CLI entrypoint wrapper with error handling."""
    try:
        app()
    except CpReviewError as exc:
        LOGGER.error("cp-review failed", extra={"event_data": {"error": str(exc)}})
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    main()
