"""Server-rendered WSGI app for the shared remediation cockpit."""

from __future__ import annotations

import json
import mimetypes
from collections.abc import Callable, Iterable
from http import cookies
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cp_review.web.db import get_active_run_job, get_recent_run_jobs, get_run, latest_run_id, list_runs, query_queue
from cp_review.web.service import (
    add_shared_campaign_member,
    add_shared_review_comment,
    authenticate_shared_user,
    build_drift,
    build_executive_summary,
    create_or_update_campaign,
    create_or_update_user,
    ensure_role,
    explain_rule,
    export_ticket_queue,
    get_rule_comments,
    load_campaign_board,
    logout_shared_user,
    persist_review_state,
    resolve_session,
    run_web_doctor,
    simulate_rule,
    start_run_job,
    sync_runs,
)

StartResponse = Callable[[str, list[tuple[str, str]]], None]


class WebApplication:
    """Shared remediation cockpit application."""

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
        session = self._current_session(environ)
        if path == "/login":
            return self._handle_login(method, environ, start_response, session)
        if path == "/logout":
            return self._handle_logout(start_response, session)
        if self.web_config.shared_mode and session is None:
            if path.startswith("/api/"):
                return self._json_response({"summary": "fail", "error": "Authentication required"}, start_response, "401 Unauthorized")
            return self._redirect(start_response, "/login")
        assert session is not None
        if path.startswith("/api/"):
            return self._dispatch_api(method, path, query, environ, start_response, session)
        return self._dispatch_page(method, path, query, start_response, session)

    def _current_session(self, environ: dict[str, Any]) -> dict[str, Any] | None:
        cookie_header = str(environ.get("HTTP_COOKIE", ""))
        if not cookie_header:
            return None
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get(self.web_config.session_cookie_name)
        if morsel is None:
            return None
        return resolve_session(self.web_config, session_id=morsel.value)

    def _render(
        self,
        template_name: str,
        context: dict[str, Any],
        start_response: StartResponse,
        status: str = "200 OK",
        headers: list[tuple[str, str]] | None = None,
    ):
        template = self.env.get_template(template_name)
        body = template.render(**context).encode("utf-8")
        response_headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))]
        if headers:
            response_headers.extend(headers)
        start_response(status, response_headers)
        return [body]

    def _json_response(
        self,
        payload: dict[str, Any],
        start_response: StartResponse,
        status: str = "200 OK",
        headers: list[tuple[str, str]] | None = None,
    ):
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        response_headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        if headers:
            response_headers.extend(headers)
        start_response(status, response_headers)
        return [body]

    def _redirect(self, start_response: StartResponse, location: str, headers: list[tuple[str, str]] | None = None):
        response_headers = [("Location", location)]
        if headers:
            response_headers.extend(headers)
        start_response("302 Found", response_headers)
        return [b""]

    def _file_response(self, file_path: Path, start_response: StartResponse):
        body = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        start_response(
            "200 OK",
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
                ("Content-Disposition", f'inline; filename="{file_path.name}"'),
            ],
        )
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

    def _set_session_cookie(self, session_id: str) -> tuple[str, str]:
        return (
            "Set-Cookie",
            f"{self.web_config.session_cookie_name}={session_id}; Path=/; HttpOnly; SameSite=Lax",
        )

    def _clear_session_cookie(self) -> tuple[str, str]:
        return (
            "Set-Cookie",
            f"{self.web_config.session_cookie_name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        )

    def _handle_login(self, method: str, environ: dict[str, Any], start_response: StartResponse, session: dict[str, Any] | None):
        if session is not None:
            return self._redirect(start_response, "/")
        error = ""
        if method == "POST":
            payload = self._read_body(environ)
            auth_result = authenticate_shared_user(
                self.web_config,
                username=str(payload.get("username", "")).strip(),
                password=str(payload.get("password", "")),
            )
            if auth_result is not None:
                return self._redirect(start_response, "/", headers=[self._set_session_cookie(str(auth_result["session"]["session_id"]))])
            error = "Invalid username or password."
        return self._render(
            "login.html.j2",
            {
                "app_title": "fw-review shared cockpit",
                "error": error,
                "bootstrap_hint": "Use the bootstrap admin credentials emitted by `cp-review web init` on first setup.",
            },
            start_response,
        )

    def _handle_logout(self, start_response: StartResponse, session: dict[str, Any] | None):
        logout_shared_user(self.web_config, session_id=str(session["session_id"]) if session else None)
        return self._redirect(start_response, "/login", headers=[self._clear_session_cookie()])

    def _base_context(self, *, current: str, session: dict[str, Any]) -> dict[str, Any]:
        latest = latest_run_id(self.web_config.db_path)
        latest_run = get_run(self.web_config.db_path, latest) if latest else None
        return {
            "current": current,
            "app_title": "fw-review remediation cockpit",
            "latest_run": latest_run,
            "active_job": get_active_run_job(self.web_config.db_path),
            "current_user": session,
        }

    def _dispatch_page(self, method: str, path: str, query: dict[str, str], start_response: StartResponse, session: dict[str, Any]):
        if method != "GET":
            return self._json_response({"summary": "fail", "error": "Method not allowed"}, start_response, "405 Method Not Allowed")
        if path == "/":
            runs = list_runs(self.web_config.db_path, limit=8)
            latest = get_run(self.web_config.db_path, runs[0]["run_id"]) if runs else None
            context = {
                **self._base_context(current="overview", session=session),
                "runs": runs,
                "overview": latest,
                "executive": build_executive_summary(self.web_config),
            }
            return self._render("overview.html.j2", context, start_response)
        if path == "/executive":
            return self._render(
                "executive.html.j2",
                {**self._base_context(current="executive", session=session), "executive": build_executive_summary(self.web_config)},
                start_response,
            )
        if path == "/campaigns":
            return self._render(
                "campaigns.html.j2",
                {**self._base_context(current="campaigns", session=session), **load_campaign_board(self.web_config)},
                start_response,
            )
        if path == "/runs":
            return self._render("runs.html.j2", {**self._base_context(current="runs", session=session), "runs": list_runs(self.web_config.db_path, limit=50)}, start_response)
        if path.startswith("/runs/"):
            run_id = path.split("/", 2)[2]
            run = get_run(self.web_config.db_path, run_id)
            if run is None:
                return self._render("error.html.j2", {**self._base_context(current="runs", session=session), "message": f"Run not found: {run_id}"}, start_response, "404 Not Found")
            queue_items = query_queue(self.web_config.db_path, run_id=run_id, limit=20)
            return self._render("run_detail.html.j2", {**self._base_context(current="runs", session=session), "run": run, "queue_items": queue_items}, start_response)
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
                "sort_by": query.get("sort_by") or "priority",
                "sort_dir": query.get("sort_dir") or "desc",
            }
            items = query_queue(
                self.web_config.db_path,
                run_id=filters["run_id"],
                package=filters["package"],
                layer=filters["layer"],
                action_type=filters["action_type"],
                priority=filters["priority"],
                status=filters["status"],
                owner=filters["owner"],
                campaign=filters["campaign"],
                sort_by=str(filters["sort_by"]),
                sort_dir=str(filters["sort_dir"]),
                limit=500,
            )
            activity = get_recent_run_jobs(self.web_config.db_path, limit=5)
            return self._render(
                "queue.html.j2",
                {
                    **self._base_context(current="queue", session=session),
                    "items": items,
                    "filters": filters,
                    "runs": list_runs(self.web_config.db_path, limit=20),
                    "recent_jobs": activity,
                    "campaigns": load_campaign_board(self.web_config)["campaigns"],
                },
                start_response,
            )
        if path.startswith("/rules/"):
            rule_uid = path.split("/", 2)[2]
            detail_run_id: str | None = query.get("run_id") or latest_run_id(self.web_config.db_path)
            payload = explain_rule(self.settings, self.web_config, rule_uid=rule_uid, run_id=detail_run_id)
            comments = get_rule_comments(self.web_config, run_id=detail_run_id)
            return self._render(
                "rule_detail.html.j2",
                {
                    **self._base_context(current="queue", session=session),
                    "payload": payload,
                    "run_id": detail_run_id,
                    "comments": [comment for comment in comments if comment["rule_uid"] == rule_uid],
                },
                start_response,
            )
        if path.startswith("/simulate/"):
            rule_uid = path.split("/", 2)[2]
            simulate_run_id = query.get("run_id") or latest_run_id(self.web_config.db_path)
            payload = simulate_rule(self.settings, self.web_config, rule_uid=rule_uid, run_id=simulate_run_id)
            return self._render(
                "simulate.html.j2",
                {**self._base_context(current="simulate", session=session), "payload": payload, "run_id": simulate_run_id},
                start_response,
            )
        if path == "/drift":
            drift = build_drift(self.settings, previous_run_id=query.get("previous_run_id"), current_run_id=query.get("current_run_id"))
            return self._render("drift.html.j2", {**self._base_context(current="drift", session=session), **drift, "runs": list_runs(self.web_config.db_path, limit=20)}, start_response)
        if path.startswith("/artifacts/"):
            _, _, run_id, artifact_name = path.split("/", 3)
            run = get_run(self.web_config.db_path, run_id)
            if run is None:
                return self._render("error.html.j2", {**self._base_context(current="runs", session=session), "message": f"Run not found: {run_id}"}, start_response, "404 Not Found")
            artifact = next((item for item in run["artifacts"] if item["name"] == artifact_name), None)
            if artifact is None:
                return self._render("error.html.j2", {**self._base_context(current="runs", session=session), "message": f"Artifact not found: {artifact_name}"}, start_response, "404 Not Found")
            artifact_path = Path(str(artifact["path"]))
            if not artifact_path.exists():
                return self._render("error.html.j2", {**self._base_context(current="runs", session=session), "message": f"Artifact missing on disk: {artifact_name}"}, start_response, "404 Not Found")
            return self._file_response(artifact_path, start_response)
        if path == "/settings":
            return self._render(
                "settings.html.j2",
                {
                    **self._base_context(current="settings", session=session),
                    "settings": self.settings.sanitized_summary(),
                    "web_config": self.web_config.model_dump(mode="json"),
                    "recent_jobs": get_recent_run_jobs(self.web_config.db_path),
                },
                start_response,
            )
        if path == "/health":
            report = run_web_doctor(self.settings, self.web_config, web_config_path=self.web_config_path)
            return self._render("health.html.j2", {**self._base_context(current="health", session=session), "report": report}, start_response)
        return self._render("error.html.j2", {**self._base_context(current="unknown", session=session), "message": f"Unknown route: {path}"}, start_response, "404 Not Found")

    def _dispatch_api(self, method: str, path: str, query: dict[str, str], environ: dict[str, Any], start_response: StartResponse, session: dict[str, Any]):
        if path == "/api/run" and method == "POST":
            if not ensure_role(session, "approver"):
                return self._json_response({"summary": "fail", "error": "Approver role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            result = start_run_job(self.settings, self.web_config, strict_validate=bool(payload.get("strict_validate", self.web_config.launch_strict_validate)))
            status = "202 Accepted" if result.get("summary") == "ok" else "409 Conflict"
            return self._json_response(result, start_response, status)
        if path == "/api/queue/sync" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            report = sync_runs(self.settings, self.web_config, run_id=payload.get("run_id") or None)
            return self._json_response(report, start_response)
        if path == "/api/review-state" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
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
                approval_status=payload.get("approval_status") or None,
                owner=payload.get("owner") or None,
                campaign=payload.get("campaign") or None,
                due_date=payload.get("due_date") or None,
                notes=payload.get("notes") or None,
                changed_by=str(session.get("username", "system")),
            )
            return self._json_response(result, start_response)
        if path == "/api/comments" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            comment = add_shared_review_comment(
                self.web_config,
                item_id=str(payload["item_id"]),
                comment=str(payload["comment"]),
                author=str(session.get("username", "system")),
            )
            return self._json_response({"summary": "ok", "comment": comment}, start_response)
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
        if path == "/api/tickets/export" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            run_id = payload.get("run_id") or latest_run_id(self.web_config.db_path)
            output_path = self.settings.collection.output_dir / "reports" / str(run_id) / "ticket-drafts.json"
            exported = export_ticket_queue(
                self.web_config,
                run_id=str(run_id) if run_id else None,
                base_url=f"http://{self.web_config.host}:{self.web_config.port}",
                output_path=output_path,
            )
            return self._json_response({"summary": "ok", "output_path": str(exported), "run_id": run_id}, start_response)
        if path == "/api/users" and method == "POST":
            if not ensure_role(session, "admin"):
                return self._json_response({"summary": "fail", "error": "Admin role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            created = create_or_update_user(
                self.web_config,
                username=str(payload["username"]),
                role=str(payload.get("role", "viewer")),
                password=str(payload["password"]),
            )
            return self._json_response({"summary": "ok", "user": created}, start_response)
        if path == "/api/campaigns" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            created = create_or_update_campaign(
                self.web_config,
                campaign_key=str(payload["campaign_key"]),
                name=str(payload.get("name") or payload["campaign_key"]),
                owner=str(payload.get("owner") or session["username"]),
                summary=str(payload.get("summary") or ""),
                status=str(payload.get("status") or "active"),
                due_date=str(payload["due_date"]) if payload.get("due_date") else None,
            )
            return self._json_response({"summary": "ok", "campaign": created}, start_response)
        if path == "/api/campaign-members" and method == "POST":
            if not ensure_role(session, "reviewer"):
                return self._json_response({"summary": "fail", "error": "Reviewer role required"}, start_response, "403 Forbidden")
            payload = self._read_body(environ)
            created = add_shared_campaign_member(
                self.web_config,
                campaign_key=str(payload["campaign_key"]),
                username=str(payload["username"]),
                role=str(payload.get("role") or "member"),
            )
            return self._json_response({"summary": "ok", "member": created}, start_response)
        return self._json_response({"summary": "fail", "error": f"Unsupported API route: {method} {path}"}, start_response, "404 Not Found")
