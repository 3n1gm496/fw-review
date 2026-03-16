"""Readiness checks for office/prod execution."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cp_review.config import AppConfig


def run_local_readiness_checks(settings: AppConfig) -> dict[str, Any]:
    """Run local non-network checks and return a structured report."""
    checks: list[dict[str, str]] = []

    output_dir = settings.collection.output_dir
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_probe = output_dir / ".write_probe"
        write_probe.write_text("ok", encoding="utf-8")
        write_probe.unlink(missing_ok=True)
        checks.append({"name": "output_dir_writable", "status": "ok", "details": str(output_dir)})
    except OSError as exc:
        checks.append({"name": "output_dir_writable", "status": "fail", "details": str(exc)})

    if settings.management.ca_bundle:
        bundle_path = Path(settings.management.ca_bundle)
        if bundle_path.exists():
            checks.append({"name": "ca_bundle_path", "status": "ok", "details": str(bundle_path)})
        else:
            checks.append({"name": "ca_bundle_path", "status": "fail", "details": f"Missing file: {bundle_path}"})
    else:
        checks.append({"name": "ca_bundle_path", "status": "warn", "details": "No CA bundle configured"})

    username_present = bool(os.getenv(settings.management.username_env))
    password_present = bool(os.getenv(settings.management.password_env))
    if username_present and password_present:
        checks.append(
            {
                "name": "credentials_env",
                "status": "ok",
                "details": f"{settings.management.username_env} and {settings.management.password_env} set",
            }
        )
    else:
        checks.append(
            {
                "name": "credentials_env",
                "status": "warn",
                "details": f"Missing one or both env vars: {settings.management.username_env}, {settings.management.password_env}",
            }
        )

    has_fail = any(item["status"] == "fail" for item in checks)
    return {
        "summary": "fail" if has_fail else "ok",
        "checks": checks,
    }
