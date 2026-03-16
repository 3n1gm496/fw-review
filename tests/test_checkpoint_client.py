from __future__ import annotations

import json
from collections import deque
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from cp_review.checkpoint_client import CheckPointClient
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.exceptions import CheckPointApiError, ReadOnlyViolationError


def _build_settings(*, max_retries: int = 4) -> AppConfig:
    return AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
            max_retries=max_retries,
        ),
        collection=CollectionConfig(),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def _mock_client(client: CheckPointClient, handler) -> None:
    client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(handler), base_url=client.base_url)  # type: ignore[assignment]


def test_call_api_blocks_mutating_command():
    client = CheckPointClient(_build_settings())
    try:
        with pytest.raises(ReadOnlyViolationError):
            client.call_api("set-access-rule", {"uid": "rule-1"})
    finally:
        client.close()


def test_call_api_allows_read_only_command_with_prefix():
    client = CheckPointClient(_build_settings())
    try:
        client._request = lambda command, payload, allow_unsafe=False: {"command": command, "payload": payload}  # type: ignore[method-assign]
        data = client.call_api("show-access-rulebase", {"name": "Network"})
        assert data["command"] == "show-access-rulebase"
        assert data["payload"]["name"] == "Network"
    finally:
        client.close()


def test_login_sets_sid_and_sends_credentials():
    captured_payloads: list[dict[str, Any]] = []
    client = CheckPointClient(_build_settings())

    def handler(request: httpx.Request) -> httpx.Response:
        captured_payloads.append(json.loads(request.content.decode("utf-8")))
        assert request.url.path == "/web_api/login"
        return httpx.Response(200, json={"sid": "sid-123"}, request=request)

    _mock_client(client, handler)
    try:
        sid = client.login()
    finally:
        client.close()

    assert sid == "sid-123"
    assert client.sid == "sid-123"
    assert captured_payloads == [{"user": "user", "password": "pass"}]


def test_login_requires_sid_in_response():
    client = CheckPointClient(_build_settings())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={}, request=request)

    _mock_client(client, handler)
    try:
        with pytest.raises(CheckPointApiError, match="session ID"):
            client.login()
    finally:
        client.close()


def test_call_api_sends_sid_header_after_login():
    headers_seen: list[str | None] = []
    responses = deque(
        [
            {"sid": "sid-123"},
            {"packages": [], "total": 0},
        ]
    )
    client = CheckPointClient(_build_settings())

    def handler(request: httpx.Request) -> httpx.Response:
        headers_seen.append(request.headers.get("X-chkp-sid"))
        return httpx.Response(200, json=responses.popleft(), request=request)

    _mock_client(client, handler)
    try:
        client.login()
        payload = client.call_api("show-packages", {"limit": 1})
    finally:
        client.close()

    assert payload["total"] == 0
    assert headers_seen == [None, "sid-123"]


def test_logout_clears_sid_even_if_request_fails():
    client = CheckPointClient(_build_settings())
    client.sid = "sid-123"

    def failing_request(command: str, payload: dict[str, Any], *, allow_unsafe: bool = False) -> dict[str, Any]:
        raise CheckPointApiError(f"{command} failed")

    client._request = failing_request  # type: ignore[method-assign]

    with pytest.raises(CheckPointApiError):
        client.logout()
    assert client.sid is None


def test_request_raises_api_error_on_http_status_failure():
    client = CheckPointClient(_build_settings(max_retries=1))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom", request=request)

    _mock_client(client, handler)
    try:
        with pytest.raises(CheckPointApiError, match="HTTP error calling show-packages: 500 boom"):
            client.call_api("show-packages", {"limit": 1})
    finally:
        client.close()


def test_request_raises_api_error_on_api_payload_error():
    client = CheckPointClient(_build_settings(max_retries=1))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": "generic_err", "message": "bad request"}, request=request)

    _mock_client(client, handler)
    try:
        with pytest.raises(CheckPointApiError, match="API error calling show-packages: generic_err bad request"):
            client.call_api("show-packages", {"limit": 1})
    finally:
        client.close()


def test_request_raises_api_error_on_non_object_response():
    client = CheckPointClient(_build_settings(max_retries=1))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"], request=request)

    _mock_client(client, handler)
    try:
        with pytest.raises(CheckPointApiError, match="Unexpected non-object response"):
            client.call_api("show-packages", {"limit": 1})
    finally:
        client.close()


def test_request_retries_transport_errors_then_succeeds(monkeypatch: pytest.MonkeyPatch):
    attempts = {"count": 0}
    client = CheckPointClient(_build_settings(max_retries=2))

    class ImmediateRetrying:
        def __init__(self, *, stop, wait, retry, reraise):
            self.stop = stop

        def __call__(self, fn):
            last_error: Exception | None = None
            for _ in range(2):
                try:
                    return fn()
                except httpx.TransportError as exc:
                    last_error = exc
            assert last_error is not None
            raise last_error

    def flaky_post(path: str, *, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        attempts["count"] += 1
        request = httpx.Request("POST", f"{client.base_url}{path}", json=json, headers=headers)
        if attempts["count"] == 1:
            raise httpx.TransportError("temporary network issue")
        return httpx.Response(200, json={"packages": [], "total": 0}, request=request)

    monkeypatch.setattr("cp_review.checkpoint_client.Retrying", ImmediateRetrying)
    client._client.post = flaky_post  # type: ignore[method-assign]

    try:
        payload = client.call_api("show-packages", {"limit": 1})
    finally:
        client.close()

    assert payload["total"] == 0
    assert attempts["count"] == 2
    assert client.api_call_count == 2
    assert client.command_counts["show-packages"] == 2


def test_context_manager_logs_in_and_logs_out(monkeypatch: pytest.MonkeyPatch):
    client = CheckPointClient(_build_settings())
    called: list[str] = []

    def fake_login() -> str:
        called.append("login")
        client.sid = "sid-123"
        return "sid-123"

    def fake_logout() -> None:
        called.append("logout")
        client.sid = None

    def fake_close() -> None:
        called.append("close")

    monkeypatch.setattr(client, "login", fake_login)
    monkeypatch.setattr(client, "logout", fake_logout)
    monkeypatch.setattr(client, "close", fake_close)

    with client as entered:
        assert entered is client
        assert client.sid == "sid-123"

    assert called == ["login", "logout", "close"]
