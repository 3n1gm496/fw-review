"""Typer CLI for cp-review."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from cp_review.analyzers import analyze_dataset
from cp_review.checkpoint_client import CheckPointClient
from cp_review.collectors.logs import collect_logs_for_rule_uids
from cp_review.collectors.packages import collect_policy_snapshot
from cp_review.config import apply_cli_overrides, build_run_paths, latest_file, load_settings
from cp_review.exceptions import CpReviewError
from cp_review.logging_conf import configure_logging
from cp_review.normalize.dataset import load_dataset, save_dataset
from cp_review.provenance import write_provenance_file
from cp_review.reports.csv_writer import write_findings_csv
from cp_review.reports.html_writer import write_html_report
from cp_review.reports.json_writer import write_findings_json

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


def _write_findings_bundle(findings, reports_dir: Path, settings, dataset) -> Path:
    findings_json = reports_dir / "findings.json"
    findings_csv = reports_dir / "findings.csv"
    if settings.reporting.json_findings:
        write_findings_json(findings_json, findings)
    if settings.reporting.csv_findings:
        write_findings_csv(findings_csv, findings)
    if settings.reporting.html_report:
        write_html_report(reports_dir / "report.html", findings=findings, dataset=dataset, settings=settings)
    return findings_json


def _write_provenance(settings, reports_dir: Path, command: str, run_id: str, artifacts: dict[str, Path]) -> Path:
    return write_provenance_file(
        reports_dir / "provenance.json",
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
    settings = _load_config(config, env_file, ca_bundle, insecure, package)
    run_paths = build_run_paths(settings.collection.output_dir)
    with CheckPointClient(settings) as client:
        dataset = collect_policy_snapshot(client, settings, run_paths)
    dataset_path = save_dataset(run_paths.normalized_dir / "dataset.json", dataset)
    _write_provenance(
        settings,
        run_paths.reports_dir,
        "collect",
        dataset.run_id,
        artifacts={"dataset_json": dataset_path},
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
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = latest_file(settings.collection.output_dir / "normalized", "*/dataset.json")
    dataset = load_dataset(dataset_path)
    findings = analyze_dataset(dataset, settings.analysis)
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    findings_path = _write_findings_bundle(findings, reports_dir, settings, dataset)
    _write_provenance(
        settings,
        reports_dir,
        "analyze",
        dataset.run_id,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": reports_dir / "findings.json",
            "findings_csv": reports_dir / "findings.csv",
            "report_html": reports_dir / "report.html",
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
    settings = _load_config(config, env_file, None, None, None, require_credentials=False)
    if dataset_path is None:
        dataset_path = latest_file(settings.collection.output_dir / "normalized", "*/dataset.json")
    dataset = load_dataset(dataset_path)
    if findings_path is None:
        findings_path = settings.collection.output_dir / "reports" / dataset.run_id / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    report_path = write_html_report(
        settings.collection.output_dir / "reports" / dataset.run_id / "report.html",
        findings=findings,
        dataset=dataset,
        settings=settings,
    )
    reports_dir = settings.collection.output_dir / "reports" / dataset.run_id
    _write_provenance(
        settings,
        reports_dir,
        "report",
        dataset.run_id,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "report_html": reports_dir / "report.html",
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
    _write_findings_bundle(findings, run_paths.reports_dir, settings, dataset)
    _write_provenance(
        settings,
        run_paths.reports_dir,
        "full-run",
        dataset.run_id,
        artifacts={
            "dataset_json": run_paths.normalized_dir / "dataset.json",
            "findings_json": run_paths.reports_dir / "findings.json",
            "findings_csv": run_paths.reports_dir / "findings.csv",
            "report_html": run_paths.reports_dir / "report.html",
        },
    )
    typer.echo(f"Full run completed: {dataset_path}")


def main() -> None:
    """CLI entrypoint wrapper with error handling."""
    try:
        app()
    except CpReviewError as exc:
        LOGGER.error("cp-review failed", extra={"event_data": {"error": str(exc)}})
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    main()
