"""
Unit and integration tests for @madps/agent Client SDK and Python middleware.
Verifies header redaction, circuit breaker fail-safe mechanics, and non-blocking telemetry forwarding.
"""

import time
import pytest
from madps_agent_sdk import (
    CircuitBreaker,
    DEFAULT_REDACTED_HEADERS,
    MADPSAgentClient,
)


def test_header_sanitization():
    """Verify sensitive tokens, cookies, and API keys are stripped before telemetry dispatch."""
    client = MADPSAgentClient(api_key="mk_live_test123")

    dirty_headers = {
        "Authorization": "Bearer sensitive_jwt_token_xyz",
        "Cookie": "session_id=secret_cookie_9918",
        "Set-Cookie": "auth=123",
        "X-Api-Key": "mk_live_secret",
        "X-CSRF-Token": "csrf_secret_abc",
        "User-Agent": "Mozilla/5.0",
        "Host": "api.acme.com",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }

    clean = client.sanitize_headers(dirty_headers)

    # Sensitive headers must be absent
    assert "authorization" not in clean
    assert "cookie" not in clean
    assert "set-cookie" not in clean
    assert "x-api-key" not in clean
    assert "x-csrf-token" not in clean

    # Non-sensitive security telemetry headers must be preserved
    assert clean["user-agent"] == "Mozilla/5.0"
    assert clean["host"] == "api.acme.com"
    assert clean["content-type"] == "application/json"


def test_circuit_breaker_tripping_and_recovery():
    """Verify circuit breaker opens after 3 failures and protects client application from hanging."""
    breaker = CircuitBreaker(threshold=3, reset_timeout_seconds=0.2)

    assert breaker.can_attempt() is True
    assert breaker.is_open is False

    # 1st failure
    breaker.record_failure()
    assert breaker.can_attempt() is True
    assert breaker.is_open is False

    # 2nd failure
    breaker.record_failure()
    assert breaker.can_attempt() is True
    assert breaker.is_open is False

    # 3rd failure: threshold reached -> circuit opens
    breaker.record_failure()
    assert breaker.is_open is True
    assert breaker.can_attempt() is False

    # Immediate next attempt should be blocked
    assert breaker.can_attempt() is False

    # Wait for cooldown reset timeout
    time.sleep(0.25)

    # Circuit should now allow a retry (half-open)
    assert breaker.can_attempt() is True

    # On success, circuit resets
    breaker.record_success()
    assert breaker.is_open is False
    assert breaker.failure_count == 0


def test_client_fails_silently_on_unreachable_server():
    """Verify client does not crash or raise exceptions when backend endpoint is unreachable."""
    unreachable_client = MADPSAgentClient(
        api_key="mk_live_test_unreachable",
        endpoint="http://127.0.0.1:59999/api/v1/ingest/log",  # Unreachable port
        timeout_seconds=0.1,
    )

    # Synchronous forward should catch exception gracefully and trip circuit
    unreachable_client.forward_sync({
        "timestamp": "2026-09-05T00:00:00Z",
        "method": "GET",
        "path": "/api/v1/test",
        "status_code": 200,
    })

    # Circuit breaker records the failure
    assert unreachable_client.circuit_breaker.failure_count == 1
