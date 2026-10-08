"""
Branch 2: Semantic Payload Evaluator.
Performs deterministic AST and semantic pattern matching for injection attacks:
SQLi, RCE, SSTI, Path Traversal, XXE, XSS, and Insecure Deserialization.
"""

from __future__ import annotations

import re
from typing import Any, Dict


class SemanticBranch:
    """Evaluates payload semantics against known injection attack grammars."""

    name = "semantic_payload_evaluator"

    PATTERNS = {
        "SQLi": [
            r"(?i)(\bUNION\b\s+SELECT\b)",
            r"(?i)(\bSELECT\b.+\bFROM\b)",
            r"(?i)(\bOR\b\s+1\s*=\s*1\b)",
            r"(?i)(--\s*$|;\s*--)",
            r"(?i)('\s*OR\s*')",
        ],
        "RCE": [
            r"(?i)(;\s*curl\b|;\s*wget\b|;\s*bash\b|;\s*sh\b)",
            r"(?i)(\|\s*bash\b|\|\s*sh\b)",
            r"(?i)(`.*`)",
            r"(?i)(\$\(.*\))",
            r"(?i)(powershell\s+-enc)",
        ],
        "SSTI": [
            r"(\{\{.*config.*\}\})",
            r"(\{\{.*__class__.*\}\})",
            r"(\$\{.*T\(.*\).*\})",
            r"(\{\{\s*7\s*\*\s*7\s*\}\})",
        ],
        "PATH_TRAVERSAL": [
            r"(\.\./\.\./)",
            r"(%2e%2e%2f)",
            r"(/etc/passwd|/windows/win\.ini)",
        ],
        "XXE": [
            r"(?i)(<!DOCTYPE\s+\w+\s+\[<!ENTITY\s+\w+\s+SYSTEM)",
            r"(?i)(<!ENTITY\s+%\s+\w+\s+SYSTEM)",
        ],
        "STORED_XSS": [
            r"(?i)(<script.*?>.*?</script>)",
            r"(?i)(<img\s+.*?onerror\s*=)",
            r"(?i)(javascript:\s*alert)",
            r"(?i)(document\.cookie)",
        ],
        "DESERIALIZATION": [
            r"(rO0ABXNyABF)",  # Java serialized object magic bytes in base64
            r"(cos\nsystem\n)",  # Python pickle opcode
        ],
    }

    @classmethod
    def evaluate(cls, telemetry: Dict[str, Any]) -> float:
        text = str(telemetry.get("payload", "")) + " " + str(telemetry.get("body", "")) + " " + str(telemetry.get("query", "")) + " " + str(telemetry.get("path_param", "")) + " " + str(telemetry.get("cookie_header", ""))
        
        max_score = 0.05
        for cat, patterns in cls.PATTERNS.items():
            for p in patterns:
                if re.search(p, text):
                    max_score = max(max_score, 0.98 if cat in ["RCE", "SQLi", "SSTI"] else 0.94)
                    break
        return max_score

    @classmethod
    def identify_category(cls, telemetry: Dict[str, Any]) -> Optional[str]:
        text = str(telemetry.get("payload", "")) + " " + str(telemetry.get("body", "")) + " " + str(telemetry.get("query", "")) + " " + str(telemetry.get("path_param", ""))
        for cat, patterns in cls.PATTERNS.items():
            for p in patterns:
                if re.search(p, text):
                    return cat
        return None
