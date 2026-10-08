"""
MAD-PS Client Integration SDK for Python (ASGI / Starlette / FastAPI / Flask / Requests).
Non-blocking, circuit-broken telemetry forwarding middleware for MAD-PS AI-Powered SOC.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set
import httpx

logger = logging.getLogger("madps.agent")

DEFAULT_REDACTED_HEADERS: Set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "session-token",
    "jwt",
}

DEFAULT_IGNORED_EXTENSIONS = re.compile(r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$", re.IGNORECASE)
DEFAULT_IGNORED_PATHS: Set[str] = {"/health", "/healthz", "/favicon.ico", "/ping"}


class CircuitBreaker:
    """Fail-safe circuit breaker preventing client slowdowns during backend degradation."""

    def __init__(self, threshold: int = 3, reset_timeout_seconds: float = 30.0) -> None:
        self.threshold = threshold
        self.reset_timeout = reset_timeout_seconds
        self.failure_count = 0
        self.is_open = False
        self.last_failure_time = 0.0

    def record_success(self) -> None:
        self.failure_count = 0
        self.is_open = False

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            self.is_open = True

    def can_attempt(self) -> bool:
        if not self.is_open:
            return True
        if time.time() - self.last_failure_time >= self.reset_timeout:
            self.is_open = False
            self.failure_count = 0
            return True
        return False


class MADPSAgentClient:
    """High-performance non-blocking client for forwarding telemetry to MAD-PS."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = "http://127.0.0.1:8000/api/v1/ingest/log",
        timeout_seconds: float = 1.5,
        redacted_headers: Optional[Set[str]] = None,
        debug: bool = False,
    ) -> None:
        self.api_key = api_key or os.environ.get("MAD_PS_API_KEY", "")
        self.endpoint = endpoint or os.environ.get("MAD_PS_INGEST_URL", "http://127.0.0.1:8000/api/v1/ingest/log")
        self.timeout = timeout_seconds
        self.redacted_headers = redacted_headers or DEFAULT_REDACTED_HEADERS
        self.debug = debug
        self.circuit_breaker = CircuitBreaker()
        self._async_client: Optional[httpx.AsyncClient] = None

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        clean = {}
        for k, v in headers.items():
            if k.lower() not in self.redacted_headers:
                clean[k.lower()] = str(v)
        return clean

    def forward_sync(self, event_data: Dict[str, Any]) -> None:
        """Synchronously forward telemetry (with circuit breaker)."""
        if not self.api_key or not self.circuit_breaker.can_attempt():
            return

        headers = {
            "X-API-Key": self.api_key,
            "User-Agent": "madps-agent-py/1.0.0",
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self.endpoint,
                    json=event_data,
                    headers=headers,
                )
                if 200 <= resp.status_code < 300:
                    self.circuit_breaker.record_success()
                else:
                    self.circuit_breaker.record_failure()
        except Exception as exc:
            self.circuit_breaker.record_failure()
            if self.debug:
                logger.debug("Telemetry dispatch error: %s", exc)

    async def forward_async(self, event_data: Dict[str, Any]) -> None:
        """Asynchronously forward telemetry in background task."""
        if not self.api_key or not self.circuit_breaker.can_attempt():
            return

        headers = {
            "X-API-Key": self.api_key,
            "User-Agent": "madps-agent-py/1.0.0",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.endpoint,
                    json=event_data,
                    headers=headers,
                )
                if 200 <= resp.status_code < 300:
                    self.circuit_breaker.record_success()
                else:
                    self.circuit_breaker.record_failure()
        except Exception as exc:
            self.circuit_breaker.record_failure()
            if self.debug:
                logger.debug("Async telemetry dispatch error: %s", exc)


class MADPSASGIMiddleware:
    """ASGI Middleware for FastAPI / Starlette / Uvicorn."""

    def __init__(
        self,
        app: Any,
        api_key: Optional[str] = None,
        endpoint: str = "http://127.0.0.1:8000/api/v1/ingest/log",
        exclude_paths: Optional[List[str]] = None,
        debug: bool = False,
    ) -> None:
        self.app = app
        self.agent = MADPSAgentClient(api_key=api_key, endpoint=endpoint, debug=debug)
        self.exclude_paths = exclude_paths or []

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in DEFAULT_IGNORED_PATHS or DEFAULT_IGNORED_EXTENSIONS.search(path) or path in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        status_code = 200
        headers_raw = dict(scope.get("headers", []))
        headers_dict = {k.decode("utf-8", "ignore"): v.decode("utf-8", "ignore") for k, v in headers_raw.items()}

        async def wrapped_send(message: Dict[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            client_ip = (scope.get("client") or ("127.0.0.1", 0))[0]
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": scope.get("method", "GET"),
                "path": path,
                "query": scope.get("query_string", b"").decode("utf-8", "ignore"),
                "headers": self.agent.sanitize_headers(headers_dict),
                "status_code": status_code,
                "latency_ms": latency_ms,
                "client_ip": client_ip,
                "sdk_version": "@madps/agent-py/1.0.0",
            }
            # Fire and forget non-blocking background dispatch
            asyncio.create_task(self.agent.forward_async(event))
