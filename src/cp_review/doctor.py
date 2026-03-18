"""Readiness checks for office/prod execution."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from cp_review.config import AppConfig


def run_local_readiness_checks(settings: AppConfig, *, require_credentials: bool = True) -> dict[str, Any]:
    """Run local non-network checks and return a structured report."""
    checks: list[dict[str, str]] = []

    checks.append(
        {
            "name": "python_runtime",
            "status": "ok" if sys.version_info >= (3, 11) else "fail",
            "details": sys.version.split()[0],
        }
    )

    checks.append(
        {
            "name": "management_host",
            "status": "ok" if bool(settings.management.host) else "fail",
            "details": settings.management.host or "missing host",
        }
    )

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
        checks.append({"name": "ca_bundle_path", "status": "ok", "details": "No CA bundle configured; using system trust store"})

    review_rules_path = settings.analysis.review_rules_path
    if review_rules_path:
        checks.append(
            {
                "name": "review_rules_path",
                "status": "ok" if review_rules_path.exists() else "warn",
                "details": str(review_rules_path),
            }
        )
    else:
        checks.append(
            {
                "name": "review_rules_path",
                "status": "warn",
                "details": "No review rules file configured",
            }
        )

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
                "status": "fail" if require_credentials else "warn",
                "details": f"Missing one or both env vars: {settings.management.username_env}, {settings.management.password_env}",
            }
        )

    has_fail = any(item["status"] == "fail" for item in checks)
    return {
        "summary": "fail" if has_fail else "ok",
        "checks": checks,
    }
