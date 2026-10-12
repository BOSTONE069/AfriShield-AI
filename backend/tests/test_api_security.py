"""Tests for authentication, rate limiting, jobs, and structured errors."""

import asyncio
import time

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

import backend.app.main as main
from backend.app.schemas import AnalyzeRequest
from backend.app.security import Principal, RateLimitMiddleware, authenticate, require_analyst


def _request(path: str = "/api/runtime", headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 1234),
            "server": ("test", 80),
        }
    )


def test_authentication_and_roles_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    viewer_key = "viewer-key-with-more-than-16-characters"
    monkeypatch.setattr(main.settings, "auth_required", True)
    monkeypatch.setattr(main.settings, "api_keys", f"reviewer-alice={viewer_key}:viewer")
    request = _request()

    with pytest.raises(HTTPException) as missing:
        authenticate(request, None)
    principal = authenticate(request, viewer_key)
    with pytest.raises(HTTPException) as forbidden:
        require_analyst(request, viewer_key)

    assert missing.value.status_code == 401
    assert principal.role == "viewer"
    assert principal.key_id == "reviewer-alice"
    assert forbidden.value.status_code == 403


def test_structured_error_contains_request_id() -> None:
    request = _request()
    request.state.request_id = "test-request-1234"
    response = asyncio.run(main.http_error_handler(request, HTTPException(status_code=401, detail="Missing key")))

    assert response.status_code == 401
    assert b'"code":"authentication_required"' in response.body
    assert b'"request_id":"test-request-1234"' in response.body


def test_background_analysis_job_completes() -> None:
    principal = Principal("test-owner", "analyst")
    submitted = main.submit_analysis_job(
        AnalyzeRequest(input_type="text", content="Normal department meeting", context="Kenya"), principal
    )

    for _ in range(100):
        job = main.analysis_job(submitted["job_id"], principal)
        if job["status"] in {"completed", "failed"}:
            break
        time.sleep(0.01)

    assert job["status"] == "completed"
    assert job["result"]["threat_type"] == "BENIGN"


def test_job_access_is_owner_scoped() -> None:
    owner = Principal("owner-one", "analyst")
    submitted = main.submit_analysis_job(
        AnalyzeRequest(input_type="text", content="Normal meeting", context="Kenya"), owner
    )

    with pytest.raises(HTTPException) as forbidden:
        main.analysis_job(submitted["job_id"], Principal("owner-two", "analyst"))
    assert forbidden.value.status_code == 403
    assert main.analysis_job(submitted["job_id"], Principal("admin", "admin"))["job_id"] == submitted["job_id"]


def test_rate_limit_returns_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "rate_limit_requests", 1)
    monkeypatch.setattr(main.settings, "rate_limit_window_seconds", 60)
    middleware = RateLimitMiddleware(lambda *_args, **_kwargs: None)
    headers = [(b"x-api-key", b"isolated-rate-limit-identity")]

    async def call_next(_request: Request) -> Response:
        return Response(status_code=200)

    first = asyncio.run(middleware.dispatch(_request(headers=headers), call_next))
    second = asyncio.run(middleware.dispatch(_request(headers=headers), call_next))

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "60"


def test_technology_banner_headers_are_removed() -> None:
    middleware = main.TechnologyHeaderMiddleware(lambda *_args, **_kwargs: None)

    async def call_next(_request: Request) -> Response:
        return Response(headers={"Server": "uvicorn", "X-Powered-By": "framework", "X-Safe": "kept"})

    response = asyncio.run(middleware.dispatch(_request(), call_next))

    assert "server" not in response.headers
    assert "x-powered-by" not in response.headers
    assert response.headers["x-safe"] == "kept"


def test_rate_limit_ignores_unverified_api_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "rate_limit_requests", 1)
    monkeypatch.setattr(main.settings, "rate_limit_window_seconds", 60)
    monkeypatch.setattr(main.settings, "api_keys", "reviewer=valid-key-with-enough-length:analyst")
    middleware = RateLimitMiddleware(lambda *_args, **_kwargs: None)

    async def call_next(_request: Request) -> Response:
        return Response(status_code=200)

    def send(key: bytes) -> Response:
        return asyncio.run(middleware.dispatch(_request(headers=[(b"x-api-key", key)]), call_next))

    # Rotating fake keys from one address shares that address's bucket.
    assert send(b"random-fake-key-0001").status_code == 200
    assert send(b"random-fake-key-0002").status_code == 429
    # A valid key has its own bucket independent of the source address.
    assert send(b"valid-key-with-enough-length").status_code == 200
