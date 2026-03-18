"""Minimal server-rendered WSGI app for the remediation cockpit."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cp_review.web.db import get_active_run_job, get_recent_run_jobs, get_run, latest_run_id, list_runs, query_queue
from cp_review.web.service import (
    build_drift,
    explain_rule,
    persist_review_state,
    run_web_doctor,
    simulate_rule,
    start_run_job,
    sync_runs,
)

StartResponse = Callable[[str, list[tuple[str, str]]], None]


class WebApplication:
    """Local-first web cockpit application."""

    def __init__(self, settings, web_config, *, web_config_path: Path) -> None:
        self.settings = settings
        self.web_config = web_config
        self.web_config_path = web_config_path
        self.env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            autoescape=select_autoescape(enabled_extensions=("html",)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        if web_config.auto_sync_on_start:
            sync_runs(settings, web_config)

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = str(environ.get("PATH_INFO", "/"))
        query = {key: values[0] for key, values in parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True).items()}
        if path.startswith("/api/"):
            return self._dispatch_api(method, path, query, environ, start_response)
        return self._dispatch_page(method, path, query, start_response)

    def _render(self, template_name: str, context: dict[str, Any], start_response: StartResponse, status: str = "200 OK"):
        template = self.env.get_template(template_name)
        body = template.render(**context).encode("utf-8")
        start_response(status, [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    def _json_response(self, payload: dict[str, Any], start_response: StartResponse, status: str = "200 OK"):
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    def _read_body(self, environ: dict[str, Any]) -> dict[str, Any]:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length) if length else b""
        content_type = str(environ.get("CONTENT_TYPE", ""))
        if "application/json" in content_type and body:
            return json.loads(body.decode("utf-8"))
        if body:
            return {key: values[0] if len(values) == 1 else values for key, values in parse_qs(body.decode("utf-8"), keep_blank_values=True).items()}
        return {}

    def _base_context(self, *, current: str) -> dict[str, Any]:
        latest = latest_run_id(self.web_config.db_path)
        latest_run = get_run(self.web_config.db_path, latest) if latest else None
        return {
            "current": current,
            "app_title": "fw-review remediation cockpit",
            "latest_run": latest_run,
            "active_job": get_active_run_job(self.web_config.db_path),
        }

    def _dispatch_page(self, method: str, path: str, query: dict[str, str], start_response: StartResponse):
        if method != "GET":
            return self._json_response({"summary": "fail", "error": "Method not allowed"}, start_response, "405 Method Not Allowed")
        if path == "/":
            runs = list_runs(self.web_config.db_path, limit=8)
            latest = get_run(self.web_config.db_path, runs[0]["run_id"]) if runs else None
            context = {
                **self._base_context(current="overview"),
                "runs": runs,
                "overview": latest,
            }
            return self._render("overview.html.j2", context, start_response)
        if path == "/runs":
            return self._render("runs.html.j2", {**self._base_context(current="runs"), "runs": list_runs(self.web_config.db_path, limit=50)}, start_response)
        if path.startswith("/runs/"):
            run_id = path.split("/", 2)[2]
            run = get_run(self.web_config.db_path, run_id)
            if run is None:
                return self._render("error.html.j2", {**self._base_context(current="runs"), "message": f"Run not found: {run_id}"}, start_response, "404 Not Found")
            queue_items = query_queue(self.web_config.db_path, run_id=run_id, limit=20)
            return self._render("run_detail.html.j2", {**self._base_context(current="runs"), "run": run, "queue_items": queue_items}, start_response)
        if path == "/queue":
            selected_run_id = query.get("run_id") or latest_run_id(self.web_config.db_path)
            filters = {
                "run_id": selected_run_id,
                "package": query.get("package") or None,
                "layer": query.get("layer") or None,
                "action_type": query.get("action_type") or None,
                "priority": query.get("priority") or None,
                "status": query.get("status") or None,
                "owner": query.get("owner") or None,
                "campaign": query.get("campaign") or None,
            }
            items = query_queue(self.web_config.db_path, **filters, limit=500)
            return self._render("queue.html.j2", {**self._base_context(current="queue"), "items": items, "filters": filters, "runs": list_runs(self.web_config.db_path, limit=20)}, start_response)
        if path.startswith("/rules/"):
            rule_uid = path.split("/", 2)[2]
            detail_run_id: str | None = query.get("run_id") or latest_run_id(self.web_config.db_path)
            payload = explain_rule(self.settings, self.web_config, rule_uid=rule_uid, run_id=detail_run_id)
            return self._render(
                "rule_detail.html.j2",
                {**self._base_context(current="queue"), "payload": payload, "run_id": detail_run_id},
                start_response,
            )
        if path.startswith("/simulate/"):
            rule_uid = path.split("/", 2)[2]
            simulate_run_id = query.get("run_id") or latest_run_id(self.web_config.db_path)
            payload = simulate_rule(self.settings, self.web_config, rule_uid=rule_uid, run_id=simulate_run_id)
            return self._render(
                "simulate.html.j2",
                {**self._base_context(current="simulate"), "payload": payload, "run_id": simulate_run_id},
                start_response,
            )
        if path == "/drift":
            drift = build_drift(self.settings, previous_run_id=query.get("previous_run_id"), current_run_id=query.get("current_run_id"))
            return self._render("drift.html.j2", {**self._base_context(current="drift"), **drift, "runs": list_runs(self.web_config.db_path, limit=20)}, start_response)
        if path == "/settings":
            return self._render(
                "settings.html.j2",
                {
                    **self._base_context(current="settings"),
                    "settings": self.settings.sanitized_summary(),
                    "web_config": self.web_config.model_dump(mode="json"),
                    "recent_jobs": get_recent_run_jobs(self.web_config.db_path),
                },
                start_response,
            )
        if path == "/health":
            report = run_web_doctor(self.settings, self.web_config, web_config_path=self.web_config_path)
            return self._render("health.html.j2", {**self._base_context(current="health"), "report": report}, start_response)
        return self._render("error.html.j2", {**self._base_context(current="unknown"), "message": f"Unknown route: {path}"}, start_response, "404 Not Found")

    def _dispatch_api(self, method: str, path: str, query: dict[str, str], environ: dict[str, Any], start_response: StartResponse):
        if path == "/api/run" and method == "POST":
            payload = self._read_body(environ)
            result = start_run_job(self.settings, self.web_config, strict_validate=bool(payload.get("strict_validate", self.web_config.launch_strict_validate)))
            status = "202 Accepted" if result.get("summary") == "ok" else "409 Conflict"
            return self._json_response(result, start_response, status)
        if path == "/api/queue/sync" and method == "POST":
            payload = self._read_body(environ)
            report = sync_runs(self.settings, self.web_config, run_id=payload.get("run_id") or None)
            return self._json_response(report, start_response)
        if path == "/api/review-state" and method == "POST":
            payload = self._read_body(environ)
            item_ids = payload.get("item_ids")
            if isinstance(item_ids, str):
                item_ids = [item_ids]
            result = persist_review_state(
                self.settings,
                self.web_config,
                item_ids=item_ids if isinstance(item_ids, list) else None,
                rule_uid=payload.get("rule_uid") or None,
                status=payload.get("status") or None,
                owner=payload.get("owner") or None,
                campaign=payload.get("campaign") or None,
                due_date=payload.get("due_date") or None,
                notes=payload.get("notes") or None,
            )
            return self._json_response(result, start_response)
        if path.startswith("/api/rules/") and method == "GET":
            rule_uid = path.split("/", 3)[3]
            payload = explain_rule(self.settings, self.web_config, rule_uid=rule_uid, run_id=query.get("run_id") or None)
            return self._json_response(payload, start_response)
        if path == "/api/simulate" and method == "POST":
            payload = self._read_body(environ)
            response = simulate_rule(self.settings, self.web_config, rule_uid=str(payload["rule_uid"]), run_id=payload.get("run_id") or None)
            return self._json_response(response, start_response)
        if path == "/api/drift" and method == "POST":
            payload = self._read_body(environ)
            response = build_drift(self.settings, previous_run_id=payload.get("previous_run_id") or None, current_run_id=payload.get("current_run_id") or None)
            return self._json_response(response, start_response)
        return self._json_response({"summary": "fail", "error": f"Unsupported API route: {method} {path}"}, start_response, "404 Not Found")
