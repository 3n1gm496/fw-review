"""Typer CLI for cp-review."""

from __future__ import annotations

import json
import logging
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
from cp_review.normalize.dataset import load_dataset, save_dataset
from cp_review.provenance import write_provenance_file
from cp_review.reports.csv_writer import write_findings_csv
from cp_review.reports.html_writer import write_html_report
from cp_review.reports.json_writer import write_findings_json
from cp_review.reports.jsonl_writer import write_findings_jsonl
from cp_review.run_manifest import write_run_manifest
from cp_review.run_metrics import build_run_metrics, write_run_metrics
from cp_review.validate_run import validate_run_manifest

app = typer.Typer(add_completion=False, no_args_is_help=True)
LOGGER = logging.getLogger(__name__)


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


def _write_findings_bundle(findings, reports_dir: Path, settings, dataset) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    findings_json = reports_dir / "findings.json"
    findings_csv = reports_dir / "findings.csv"
    report_html = reports_dir / "report.html"
    findings_jsonl = reports_dir / settings.reporting.siem_jsonl_filename

    # Keep a canonical findings artifact for downstream commands and recovery.
    write_findings_json(findings_json, findings)
    artifacts["findings_json"] = findings_json
    if settings.reporting.csv_findings:
        write_findings_csv(findings_csv, findings)
        artifacts["findings_csv"] = findings_csv
    if settings.reporting.html_report:
        write_html_report(report_html, findings=findings, dataset=dataset, settings=settings)
        artifacts["report_html"] = report_html
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


def _collect_shortlist_rule_uids(findings, limit: int) -> list[str]:
    shortlist: list[str] = []
    interesting_types = {"unused_rules", "broad_allow", "no_log_rules", "high_risk_broad_usage"}
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


def _load_findings_for_report(dataset, findings_path: Path | None, settings, reports_dir: Path) -> tuple[list[Any], Path]:
    if findings_path is not None:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        return findings, findings_path

    canonical_findings = reports_dir / "findings.json"
    if canonical_findings.exists():
        findings = json.loads(canonical_findings.read_text(encoding="utf-8"))
        return findings, canonical_findings

    findings = analyze_dataset(dataset, settings.analysis)
    write_findings_json(canonical_findings, findings)
    return findings, canonical_findings


def _latest_run_manifest(reports_root: Path) -> Path:
    matches = sorted(reports_root.glob("*/run-manifest.json"), key=lambda item: (item.parent.name, item.stat().st_mtime))
    if not matches:
        raise CpReviewError(f"No run manifests found in {reports_root}")
    return matches[-1]


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
    provenance_path = _write_provenance(
        settings,
        run_paths.reports_dir,
        "collect",
        dataset.run_id,
        artifacts={"dataset_json": dataset_path, "metrics_json": metrics_path},
    )
    write_run_manifest(
        run_paths.reports_dir / "run-manifest.json",
        command="collect",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
        },
        summary={
            "api_call_count": api_call_count,
            "rules_count": len(dataset.rules),
            "warnings_count": len(dataset.warnings),
        },
    )
    typer.echo(f"Collected dataset: {dataset_path}")


@app.command()
def analyze(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    dataset_path: Path | None = typer.Option(None, "--dataset-path", dir_okay=False, help="Normalized dataset JSON."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Analyze a normalized dataset and emit findings JSON/CSV."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = latest_file(settings.collection.output_dir / "normalized", "*/dataset.json")
    dataset = load_dataset(dataset_path)
    findings = analyze_dataset(dataset, settings.analysis)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    artifacts = _write_findings_bundle(findings, reports_dir, settings, dataset)
    findings_path = artifacts.get("findings_json", reports_dir / "findings.json")
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
    provenance_path = _write_provenance(
        settings,
        reports_dir,
        "analyze",
        dataset.run_id,
        artifacts={"dataset_json": dataset_path, "metrics_json": metrics_path, **artifacts},
    )
    write_run_manifest(
        reports_dir / "run-manifest.json",
        command="analyze",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
            **artifacts,
        },
        summary={
            "findings_count": len(findings),
            "rules_count": len(dataset.rules),
            "warnings_count": len(dataset.warnings),
        },
    )
    typer.echo(f"Findings written: {findings_path}")


@app.command()
def report(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    dataset_path: Path | None = typer.Option(None, "--dataset-path", dir_okay=False, help="Normalized dataset JSON."),
    findings_path: Path | None = typer.Option(None, "--findings-path", dir_okay=False, help="Findings JSON."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Generate the HTML report from a dataset and findings."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = latest_file(settings.collection.output_dir / "normalized", "*/dataset.json")
    dataset = load_dataset(dataset_path)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    findings, findings_path = _load_findings_for_report(dataset, findings_path, settings, reports_dir)
    report_path = write_html_report(
        reports_dir / "report.html",
        findings=findings,
        dataset=dataset,
        settings=settings,
    )
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
    provenance_path = _write_provenance(
        settings,
        reports_dir,
        "report",
        dataset.run_id,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "report_html": reports_dir / "report.html",
            "metrics_json": metrics_path,
        },
    )
    write_run_manifest(
        reports_dir / "run-manifest.json",
        command="report",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "report_html": reports_dir / "report.html",
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
        },
        summary={
            "findings_count": len(findings),
            "rules_count": len(dataset.rules),
            "warnings_count": len(dataset.warnings),
        },
    )
    typer.echo(f"Report written: {report_path}")


@app.command("full-run")
def full_run(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
    ca_bundle: str | None = typer.Option(None, "--ca-bundle", help="Override CA bundle path."),
    insecure: bool | None = typer.Option(None, "--insecure/--secure", help="Lab-only TLS override."),
    package: str | None = typer.Option(None, "--package", help="Collect only the selected package."),
) -> None:
    """Run collection, analysis, and reporting in sequence."""
    configure_logging()
    started_at = perf_counter()
    settings = _load_config(config, env_file, ca_bundle, insecure, package)
    run_paths = build_run_paths(settings.collection.output_dir)
    with CheckPointClient(settings) as client:
        dataset = collect_policy_snapshot(client, settings, run_paths)
        dataset_path = save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
        findings = analyze_dataset(dataset, settings.analysis)
        if settings.collection.collect_logs_for_shortlist:
            shortlist = _collect_shortlist_rule_uids(findings, settings.collection.shortlist_log_limit)
            if shortlist:
                dataset.log_evidence.update(collect_logs_for_rule_uids(client, settings, run_paths, shortlist))
                save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
                findings = analyze_dataset(dataset, settings.analysis)
        api_call_count = client.api_call_count
        api_commands = dict(client.command_counts)
    artifacts = _write_findings_bundle(findings, run_paths.reports_dir, settings, dataset)
    metrics_path = write_run_metrics(
        run_paths.reports_dir / "metrics.json",
        build_run_metrics(
            command="full-run",
            run_id=dataset.run_id,
            settings=settings,
            duration_seconds=perf_counter() - started_at,
            api_call_count=api_call_count,
            api_commands=api_commands,
            findings_count=len(findings),
            rules_count=len(dataset.rules),
            warnings_count=len(dataset.warnings),
        ),
    )
    provenance_path = _write_provenance(
        settings,
        run_paths.reports_dir,
        "full-run",
        dataset.run_id,
        artifacts={"dataset_json": run_paths.normalized_dir / "dataset.json", "metrics_json": metrics_path, **artifacts},
    )
    write_run_manifest(
        run_paths.reports_dir / "run-manifest.json",
        command="full-run",
        run_id=dataset.run_id,
        settings=settings,
        artifacts={
            "dataset_json": run_paths.normalized_dir / "dataset.json",
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
            **artifacts,
        },
        summary={
            "api_call_count": api_call_count,
            "findings_count": len(findings),
            "rules_count": len(dataset.rules),
            "warnings_count": len(dataset.warnings),
        },
    )
    typer.echo(f"Full run completed: {dataset_path}")


@app.command()
def compare(
    config: Path = typer.Option(..., "--config", exists=True, dir_okay=False, help="Path to YAML settings file."),
    previous_findings: Path | None = typer.Option(None, "--previous-findings", dir_okay=False, help="Older findings JSON."),
    current_findings: Path | None = typer.Option(None, "--current-findings", dir_okay=False, help="Newer findings JSON."),
    output_path: Path | None = typer.Option(None, "--output-path", dir_okay=False, help="Drift output JSON path."),
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
    env_file: Path | None = typer.Option(None, "--env-file", exists=True, dir_okay=False, help="Optional .env file."),
) -> None:
    """Validate a completed run manifest and its artifacts."""
    configure_logging()
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)

    if manifest_path is None:
        reports_root = settings.collection.output_dir / "reports"
        manifest_path = reports_root / run_id / "run-manifest.json" if run_id else _latest_run_manifest(reports_root)

    report = validate_run_manifest(manifest_path)
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
