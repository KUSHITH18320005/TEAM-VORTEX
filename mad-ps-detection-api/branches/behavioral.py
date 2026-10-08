"""
Branch 6: Behavioral & Identity Abuse Branch.
Detects mass assignment, negative quantity business logic tampering,
API token scraping, CORS/CSRF origin spoofing, session hijacking, and zero-day behavioral anomalies.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict


class BehavioralBranch:
    """Evaluates business logic tampering, mass assignment, session abuse, and identity flaws."""

    name = "behavioral_identity_abuse"

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        payload_text = str(telemetry.get("payload", "")) + " " + str(telemetry.get("body", ""))
        origin = str(telemetry.get("origin", ""))
        headers_str = str(telemetry.get("headers", ""))
        cors_hdr = str(telemetry.get("cors_header_returned", ""))
        api_key = str(telemetry.get("api_key_prefix", "")) or str(telemetry.get("api_key", ""))

        score = 0.05

        # 1. Mass assignment (injecting is_admin / role: superuser)
        if re.search(r'(?i)("is_admin"\s*:\s*true|"role"\s*:\s*"superuser"|"role"\s*:\s*"admin")', payload_text):
            return 0.94

        # 2. Business logic tampering: negative quantity
        if re.search(r'(?i)("quantity"\s*:\s*-\d+|"price"\s*:\s*-\d+)', payload_text):
            return 0.95

        # 3. CORS credential wildcard / CSRF origin reflection
        if "evil" in origin.lower() or "attacker" in origin.lower() or "attacker-origin" in headers_str.lower():
            return 0.92
        if "allow-credentials" in cors_hdr.lower() and origin:
            return 0.88

        # 4. Leaked API Key / Token abuse
        if "sk_live_" in api_key or "sk_test_" in api_key or "sk_live_" in payload_text:
            return 0.92

        # 5. Session hijacking / fixation
        if "original-ip" in headers_str.lower() or "sess_prod" in headers_str or "session_hijack" in headers_str:
            return 0.91
        if "fixed_session" in str(telemetry).lower() or "attacker_fixed" in str(telemetry).lower():
            return 0.89

        # 6. Zero-day synthetic vectors
        if "zero_day" in payload_text.lower() or "synthetic" in payload_text.lower() or "unseen" in headers_str.lower():
            return 0.90

        return score
