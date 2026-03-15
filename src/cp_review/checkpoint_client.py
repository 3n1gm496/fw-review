"""HTTP client for the Check Point Management Web API."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from cp_review.config import AppConfig
from cp_review.exceptions import CheckPointApiError, ReadOnlyViolationError

LOGGER = logging.getLogger(__name__)
READ_ONLY_PREFIXES = ("show-", "list-", "query-", "where-used", "login", "logout")
FORBIDDEN_COMMAND_PREFIXES = (
    "set-",
    "add-",
    "delete-",
    "publish",
    "discard",
    "install-policy",
    "run-script",
    "take-",
)


class CheckPointClient:
    """Small transparent wrapper around the Management Web API."""

    def __init__(self, settings: AppConfig) -> None:
        """Initialize the HTTP client from application settings."""
        self.settings = settings
        self.base_url = f"https://{settings.management.host}/web_api"
        verify: bool | str = False if settings.management.insecure else (settings.management.ca_bundle or True)
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=settings.management.timeout_seconds,
            verify=verify,
            headers={"Content-Type": "application/json"},
        )
        self.sid: str | None = None

    def login(self) -> str:
        """Authenticate and return the in-memory session ID."""
        if self.settings.management.username is None or self.settings.management.password is None:
            raise CheckPointApiError("Missing management API credentials for login")
        payload = {
            "user": self.settings.management.username.get_secret_value(),
            "password": self.settings.management.password.get_secret_value(),
        }
        response = self._request("login", payload, allow_unsafe=True)
        sid = response.get("sid")
        if not sid:
            raise CheckPointApiError("Login response did not contain a session ID")
        self.sid = sid
        return sid

    def logout(self) -> None:
        """Close the current API session."""
        if not self.sid:
            return
        try:
            self._request("logout", {}, allow_unsafe=True)
        finally:
            self.sid = None

    def call_api(self, command: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a read-only Management API command."""
        self._enforce_read_only(command)
        return self._request(command, payload or {})

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def _enforce_read_only(self, command: str) -> None:
        normalized = command.strip().lower()
        if normalized.startswith(FORBIDDEN_COMMAND_PREFIXES):
            raise ReadOnlyViolationError(f"Mutating command blocked: {command}")
        if not normalized.startswith(READ_ONLY_PREFIXES):
            raise ReadOnlyViolationError(f"Command is not allowlisted as read-only: {command}")

    def _request(self, command: str, payload: dict[str, Any], *, allow_unsafe: bool = False) -> dict[str, Any]:
        if not allow_unsafe:
            self._enforce_read_only(command)

        headers: dict[str, str] = {}
        if self.sid:
            headers["X-chkp-sid"] = self.sid

        retryer = Retrying(
            stop=stop_after_attempt(self.settings.management.max_retries),
            wait=wait_exponential_jitter(initial=1, max=10),
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.TransportError)),
            reraise=True,
        )

        def do_request() -> dict[str, Any]:
            LOGGER.info(
                "Calling Check Point API",
                extra={"event_data": {"command": command, "payload_keys": sorted(payload.keys())}},
            )
            response = self._client.post(f"/{command}", json=payload, headers=headers)
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise CheckPointApiError(
                    f"HTTP error calling {command}: {exc.response.status_code} {exc.response.text}"
                ) from exc
            data = response.json()
            if not isinstance(data, dict):
                raise CheckPointApiError(f"Unexpected non-object response from {command}")
            if "code" in data and "message" in data:
                raise CheckPointApiError(f"API error calling {command}: {data['code']} {data['message']}")
            return data

        return retryer(do_request)

    def __enter__(self) -> CheckPointClient:
        """Context-manager entry."""
        self.login()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        """Context-manager exit."""
        self.logout()
        self.close()
