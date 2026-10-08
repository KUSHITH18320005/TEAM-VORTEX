"""
Branch 3: Stateful Sequence Tracker Branch.
Evaluates authorization state violations, broken tenancy access (BOLA/IDOR),
role violations (BFLA), and missing JWT signature tokens.
"""

from __future__ import annotations

import re
from typing import Any, Dict


class SequenceBranch:
    """Tracks sequence anomalies, unauthorized object tenancy, and function authorization flaws."""

    name = "stateful_sequence_tracker"

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        endpoint = str(telemetry.get("endpoint", ""))
        method = str(telemetry.get("method", "GET")).upper()
        auth_sub = str(telemetry.get("auth_sub", ""))
        caller_role = str(telemetry.get("caller_role", ""))
        jwt_header = str(telemetry.get("jwt_header", ""))

        score = 0.05

        # 1. JWT Alg: None detection (Broken Authentication)
        if "none" in jwt_header.lower():
            return 0.95

        # 2. BFLA: Standard user invoking admin endpoints
        if "/admin/" in endpoint and caller_role and caller_role != "ADMIN":
            return 0.94

        # 3. BOLA/IDOR: Object tenancy mismatch (e.g. user ID in URL != auth session sub)
        user_id_match = re.search(r"/user/(\d+)/", endpoint)
        if user_id_match and auth_sub:
            url_user_id = user_id_match.group(1)
            if url_user_id != auth_sub:
                return 0.96

        # 4. Dangerous HTTP method on privileged paths
        if method in ["DELETE", "PUT"] and ("/users/" in endpoint or "/role" in endpoint):
            if not auth_sub or caller_role == "STANDARD_USER":
                return 0.90

        return score
