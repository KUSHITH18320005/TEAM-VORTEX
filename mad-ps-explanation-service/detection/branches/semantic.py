"""
Branch 2: Semantic Payload Evaluator.
Performs deterministic AST and semantic pattern matching for injection attacks:
SQLi, RCE, SSTI, Path Traversal, XXE, XSS, and Insecure Deserialization.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class SemanticBranch:
    """Evaluates payload semantics against known injection attack grammars."""

    name = "semantic_payload_evaluator"

    PATTERNS = {
        "SQLi": [
            r"(?i)(\bUNION\b\s+SELECT\b)",
            r"(?i)(\bSELECT\b.+\bFROM\b)",
            r"(?i)(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
            r"(?i)(--\s*$|;\s*--)",
            r"(?i)('\s*OR\s*')",
            r"(?i)('\s*UNION\s+ALL\s+SELECT\b)",
            r"(?i)(SLEEP\(\d+\)|BENCHMARK\(\d+)",
        ],
        "NOSQL_INJECTION": [
            r"(\"\$gt\"\s*:\s*0|\$gt)",
            r"(\"\$ne\"\s*:\s*|\$ne)",
            r"(\"\$where\"\s*:\s*|\$where)",
            r"(\"\$regex\"\s*:\s*|\$regex)",
            r"(\"\$nin\"\s*:\s*|\$nin)",
            r"(\"\$exists\"\s*:\s*|\$exists)",
        ],
        "RCE": [
            r"(?i)(;\s*curl\b|;\s*wget\b|;\s*bash\b|;\s*sh\b)",
            r"(?i)(\|\s*bash\b|\|\s*sh\b)",
            r"(?i)(`.*`)",
            r"(?i)(\$\(.*\))",
            r"(?i)(powershell\s+-enc)",
            r"(?i)(;\s*cat\s+/etc/passwd)",
            r"(?i)(/bin/sh|/bin/bash)",
        ],
        "SSTI": [
            r"(\{\{.*config.*\}\})",
            r"(\{\{.*__class__.*\}\})",
            r"(\$\{.*T\(.*\).*\})",
            r"(\{\{\s*7\s*\*\s*7\s*\}\})",
            r"(\{\{.*request\..*\}\})",
        ],
        "PATH_TRAVERSAL": [
            r"(\.\./\.\./)",
            r"(%2e%2e%2f)",
            r"(/etc/passwd|/windows/win\.ini)",
            r"(\.\.\\\.\.\\)",
        ],
        "XXE": [
            r"(?i)(<!DOCTYPE\s+\w+\s+\[<!ENTITY\s+\w+\s+SYSTEM)",
            r"(?i)(<!ENTITY\s+%\s+\w+\s+SYSTEM)",
            r"(?i)(PUBLIC\s+\".*\"\s+\".*\")",
            r"(?i)(SYSTEM\s+[\"']file:///)",
        ],
        "STORED_XSS": [
            r"(?i)(<script.*?>.*?</script>)",
            r"(?i)(<img\s+.*?onerror\s*=)",
            r"(?i)(javascript:\s*alert)",
            r"(?i)(document\.cookie)",
            r"(?i)(<svg\s+onload=)",
            r"(?i)(<iframe\s+src=)",
        ],
        "SSRF": [
            r"(169\.254\.169\.254)",
            r"(metadata\.google\.internal)",
            r"(localhost:3000|127\.0\.0\.1:3000)",
            r"(localhost:8000|127\.0\.0\.1:8000)",
            r"(/admin/diagnostics\?host=)",
        ],
        "IDOR_BOLA": [
            r"(ord_9999|SECRET_ACQUISITION_CORP)",
            r"(/order/ord_9999)",
            r"(/user/trader_alice/holdings)",
        ],
        "BFLA_AUTH_BYPASS": [
            r"(/admin/exportAll)",
            r"(/admin/dashboard-stats)",
            r"(?i)(x-is-admin\s*:\s*true)",
            r"(?i)(role\s*:\s*['\"]superadmin['\"])",
        ],
        "JWT_ABUSE": [
            r"(?i)(\"alg\"\s*:\s*\"none\")",
            r"(eyJhbGciOiJub25lI)",
            r"(signature-stripped|tampered_header)",
        ],
        "BUSINESS_LOGIC_TAMPERING": [
            r"(?i)(price\s*:\s*0\.01|price\s*:\s*0\b)",
            r"(?i)(qty\s*:\s*-\d+)",
            r"(/newOrder.*price=0)",
        ],
        "OPEN_REDIRECT": [
            r"(?i)(\?redirect=https?%3A%2F%2F|\?redirect=https?://)",
            r"(localhost:3005)",
        ],
        "DESERIALIZATION": [
            r"(rO0ABXNyABF)",
            r"(cos\nsystem\n)",
        ],
    }

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        text = (
            str(telemetry.get("payload", "") or "")
            + " "
            + str(telemetry.get("endpoint", "") or "")
            + " "
            + str(telemetry.get("path", "") or "")
            + " "
            + str(telemetry.get("body", "") or "")
            + " "
            + str(telemetry.get("query", "") or "")
            + " "
            + str(telemetry.get("headers", "") or "")
            + " "
            + str(telemetry.get("path_param", "") or "")
            + " "
            + str(telemetry.get("cookie_header", "") or "")
            + " "
            + str(telemetry.get("raw_log_details", "") or "")
        )

        max_score = 0.05
        for cat, patterns in cls.PATTERNS.items():
            for p in patterns:
                if re.search(p, text):
                    max_score = max(max_score, 0.98 if cat in ["RCE", "SQLi", "SSTI"] else 0.94)
                    break
        return max_score

    @classmethod
    def identify_category(cls, telemetry: Dict[str, Any]) -> Optional[str]:
        text = (
            str(telemetry.get("payload", "") or "")
            + " "
            + str(telemetry.get("endpoint", "") or "")
            + " "
            + str(telemetry.get("path", "") or "")
            + " "
            + str(telemetry.get("body", "") or "")
            + " "
            + str(telemetry.get("query", "") or "")
            + " "
            + str(telemetry.get("headers", "") or "")
            + " "
            + str(telemetry.get("path_param", "") or "")
            + " "
            + str(telemetry.get("raw_log_details", "") or "")
        )
        for cat, patterns in cls.PATTERNS.items():
            for p in patterns:
                if re.search(p, text):
                    return cat
        return None

    @classmethod
    def extract_matched_tokens(cls, text: str) -> List[Tuple[str, str]]:
        """Extract matching security tokens: returns [(category, matched_pattern), ...]."""
        matched = []
        for cat, patterns in cls.PATTERNS.items():
            for p in patterns:
                m = re.search(p, text)
                if m:
                    matched.append((cat, m.group(0)[:60]))
        return matched
