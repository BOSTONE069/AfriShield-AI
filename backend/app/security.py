"""API-key authentication, role authorization, and in-process rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from backend.app.config import get_settings

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}


@dataclass(frozen=True)
class Principal:
    """Authenticated API caller without retaining the secret key."""

    key_id: str
    role: str


def _configured_keys() -> list[tuple[str, str, str]]:
    """Parse comma-separated `[reviewer=]secret:role` credentials."""
    configured: list[tuple[str, str, str]] = []
    for entry in get_settings().api_keys.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            credential, role = entry.rsplit(":", 1)
        except ValueError as exc:
            raise RuntimeError("AFRISHIELD_API_KEYS entries must use secret:role format") from exc
        if "=" in credential:
            identity, secret = credential.split("=", 1)
        else:
            secret = credential
            identity = hashlib.sha256(secret.encode()).hexdigest()[:12]
        if not re.fullmatch(r"[A-Za-z0-9._-]{2,64}", identity):
            raise RuntimeError("Reviewer identities must contain 2-64 safe characters")
        if len(secret) < 16 or role not in ROLE_RANK:
            raise RuntimeError("API keys must be at least 16 characters and use viewer, analyst, or admin role")
        configured.append((secret, role, identity))
    return configured


def security_is_configured() -> bool:
    """Return whether production authentication has at least one valid key."""
    if not get_settings().auth_required:
        return True
    try:
        return bool(_configured_keys())
    except RuntimeError:
        return False


def authenticate(request: Request, x_api_key: str | None = Header(default=None)) -> Principal:
    """Authenticate an API key using constant-time comparisons."""
    settings = get_settings()
    if not settings.auth_required:
        principal = Principal("development", "admin")
        request.state.principal = principal
        return principal
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header")
    for secret, role, identity in _configured_keys():
        if hmac.compare_digest(x_api_key, secret):
            principal = Principal(identity, role)
            request.state.principal = principal
            return principal
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def require_role(minimum_role: str):  # type: ignore[no-untyped-def]
    """Build a FastAPI dependency enforcing a minimum role."""

    def dependency(request: Request, x_api_key: str | None = Header(default=None)) -> Principal:
        principal = authenticate(request, x_api_key)
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return dependency


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Bound request bursts per API key (or source address before auth)."""

    def __init__(self, app) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        if request.url.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        raw_identity = request.headers.get("x-api-key") or (request.client.host if request.client else "unknown")
        identity = hashlib.sha256(raw_identity.encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            events = self._events[identity]
            cutoff = now - settings.rate_limit_window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= settings.rate_limit_requests:
                request_id = getattr(request.state, "request_id", "unknown")
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": {
                            "code": "rate_limit_exceeded",
                            "message": "Request rate limit exceeded.",
                            "request_id": request_id,
                        }
                    },
                    headers={"Retry-After": str(settings.rate_limit_window_seconds)},
                )
            events.append(now)
        return await call_next(request)
