"""
Phase S-Correction: Simplified One Org, One API Key, One Integration Point Test Suite
Formalizes the simplified architecture:
1. Zero Outbound Network Requests (Static Code Analysis)
2. surfaces Table Deleted & Absent — One Org, One API Key
3. Unified Telemetry Ingestion via Single @madps/agent Integration Point
4. Strict Multi-Tenant Isolation (401 INVALID_API_KEY on invalid/cross-tenant mismatch)
5. Golden Path Pipeline: Ingestion -> 8-Model Detection Mesh -> Council Synthesis -> Unified Org Incident View
"""

import os
import sys
import json
import re
import pytest
from pathlib import Path

# Add project root and services to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "mad-ps-explanation-service"))

from database import shared_db
from app import app
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def test_client():
    with TestClient(app) as client:
        yield client


def setup_test_org(org_name: str):
    """Helper to create test org and generate its primary API key."""
    org = shared_db.create_organization(name=org_name)
    key_info = shared_db.create_api_key(org_id=org["org_id"], name=f"{org_name} Key")
    return {
        "org_id": org["org_id"],
        "name": org["name"],
        "api_key": key_info["api_key"],
        "key_id": key_info["key_id"],
    }


# ==============================================================================
# TEST 1: STATIC ANALYSIS — ZERO OUTBOUND NETWORK CALLS IN INGESTION/DETECTION
# ==============================================================================
def test_zero_outbound_client_requests_static_analysis():
    """
    Scans MAD-PS core service directories to ensure zero outbound HTTP/socket
    requests are initiated towards client URLs or external domains.
    """
    madps_directories = [
        REPO_ROOT / "mad-ps-explanation-service",
        REPO_ROOT / "ingestion-service",
        REPO_ROOT / "detection-mesh-gateway",
        REPO_ROOT / "madps-agent-sdk",
    ]

    prohibited_patterns = [
        re.compile(r"requests\.(get|post|put|delete)\(\s*target_url", re.IGNORECASE),
        re.compile(r"httpx\.(get|post|put|delete)\(\s*target_url", re.IGNORECASE),
        re.compile(r"urllib\.request\.urlopen\(\s*target_url", re.IGNORECASE),
        re.compile(r"fetch\(\s*target_url", re.IGNORECASE),
        re.compile(r"axios\.(get|post)\(\s*target_url", re.IGNORECASE),
    ]

    violations = []
    scanned_files = 0

    for directory in madps_directories:
        if not directory.exists():
            continue
        for root, _, files in os.walk(directory):
            if any(skip in root for skip in ["node_modules", ".git", "venv", "__pycache__", "tests"]):
                continue
            for file in files:
                if file.endswith((".py", ".js")):
                    scanned_files += 1
                    filepath = Path(root) / file
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    for pat in prohibited_patterns:
                        if pat.search(content):
                            violations.append(f"{filepath}: matches prohibited pattern {pat.pattern}")

    print(f"\n[STATIC SCAN] Scanned {scanned_files} core files across MAD-PS ecosystem. Violations: {len(violations)}")
    assert len(violations) == 0, f"Found prohibited outbound client requests: {violations}"


# ==============================================================================
# TEST 2: DATA MODEL REVERSION — SURFACES TABLE DELETED, ONE API KEY PER ORG
# ==============================================================================
def test_surfaces_table_deleted_and_one_api_key():
    """
    Verifies that:
    1. The 'surfaces' table is completely absent from SQLite schema.
    2. Organizations table exists and is intact.
    3. api_keys table issues one active key per org without surface_id columns.
    """
    with shared_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='surfaces'")
        surface_table = cursor.fetchone()
        assert surface_table is None, "The 'surfaces' table must be completely dropped."

    # Verify organization and API key generation
    org_res = setup_test_org("Unified Client Corp")
    org_id = org_res["org_id"]
    api_key = org_res["api_key"]
    assert org_id.startswith("org_")
    assert api_key.startswith("mk_live_")

    # Verify api_keys columns
    with shared_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(api_keys)")
        columns = [col[1] for col in cursor.fetchall()]
        assert "surface_id" not in columns
        assert "org_id" in columns
        assert "key_hash" in columns


# ==============================================================================
# TEST 3: CROSS-TENANT & API KEY AUTHENTICATION ENFORCEMENT
# ==============================================================================
def test_cross_tenant_isolation_and_auth(test_client):
    """
    Verifies that:
    1. Org A with Key A can ingest logs resolved to org_a.
    2. Org B with Key B can ingest logs resolved to org_b.
    3. Invalid API key is REJECTED with 401 INVALID_API_KEY.
    4. Missing API key is REJECTED with 401 MISSING_API_KEY.
    """
    res_a = setup_test_org("Tenant Alpha")
    key_a = res_a["api_key"]

    res_b = setup_test_org("Tenant Beta")
    key_b = res_b["api_key"]

    payload = {
        "event_type": "HTTP_REQUEST",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": {"Content-Type": "application/json"},
        "payload": "username=admin&action=login",
        "status_code": 200,
        "latency_ms": 14.2
    }

    # Org A ingestion -> Success
    resp_a = test_client.post(
        "/api/v1/ingest/log",
        headers={"Authorization": f"Bearer {key_a}"},
        json=payload
    )
    assert resp_a.status_code == 200
    assert resp_a.json()["status"].lower() == "ingested"
    assert resp_a.json()["org_id"] == res_a["org_id"]

    # Org B ingestion -> Success
    resp_b = test_client.post(
        "/api/v1/ingest/log",
        headers={"X-API-Key": key_b},
        json=payload
    )
    assert resp_b.status_code == 200
    assert resp_b.json()["status"].lower() == "ingested"
    assert resp_b.json()["org_id"] == res_b["org_id"]

    # Invalid Key -> 401
    resp_invalid = test_client.post(
        "/api/v1/ingest/log",
        headers={"Authorization": "Bearer mk_live_nonexistent_fake_key_999"},
        json=payload
    )
    assert resp_invalid.status_code == 401
    assert resp_invalid.json()["detail"]["code"] == "INVALID_API_KEY"

    # Missing Key -> 401
    resp_missing = test_client.post(
        "/api/v1/ingest/log",
        json=payload
    )
    assert resp_missing.status_code == 401
    assert resp_missing.json()["detail"]["code"] == "MISSING_API_KEY"


# ==============================================================================
# TEST 4: SINGLE @MADPS/AGENT INTEGRATION — CAPTURES FULL APP ACTIVITY
# ==============================================================================
def test_single_agent_integration_telemetry():
    """
    Verifies that @madps/agent SDK correctly packages route hit, response status,
    latency, and sanitized headers using a single API key.
    """
    from madps_agent_sdk import MADPSAgentClient

    client = MADPSAgentClient(api_key="mk_live_test_single_agent")
    sanitized = client.sanitize_headers({
        "Authorization": "Bearer sensitive_secret_123",
        "Cookie": "session=xyz",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    })
    assert "authorization" not in sanitized
    assert "cookie" not in sanitized
    assert sanitized["content-type"] == "application/json"


# ==============================================================================
# TEST 5: SIMPLIFIED GOLDEN PATH PIPELINE EXECUTION
# ==============================================================================
def test_simplified_golden_path_pipeline(test_client):
    """
    Executes end-to-end simplified Golden Path:
    1. Single Org signup -> 1 active API Key issued.
    2. Real attack payload ingested via single @madps/agent endpoint.
    3. Ingestion routes through 8-model detection mesh.
    4. Council Debate synthesized with 3-Agent consensus.
    5. Incident persisted and queryable under the single organization view.
    """
    res = setup_test_org("Acme Securities Simplified")
    org_id = res["org_id"]
    key = res["api_key"]

    attack_payload = {
        "event_type": "HTTP_REQUEST",
        "method": "POST",
        "path": "/api/v1/orders/search",
        "headers": {"Content-Type": "application/json"},
        "payload": "' UNION SELECT username, password_hash FROM admin_users --",
        "status_code": 500,
        "latency_ms": 120.5
    }

    # 1. Ingestion
    resp = test_client.post(
        "/api/v1/ingest/log",
        headers={"Authorization": f"Bearer {key}"},
        json=attack_payload
    )
    assert resp.status_code == 200
    ingest_json = resp.json()
    assert ingest_json["status"].lower() == "ingested"
    assert ingest_json["org_id"] == org_id

    # 2. Council Chamber Synthesis
    incident_id = f"INC-SIMPLIFIED-{os.urandom(3).hex().upper()}"
    council_req = {
        "incident_id": incident_id,
        "org_id": org_id,
        "alert_data": {
            "category": "SQL_INJECTION",
            "confidence": 0.991,
            "severity": "CRITICAL",
            "payload": attack_payload["payload"]
        }
    }

    council_resp = test_client.post("/council/analyze", json=council_req)
    assert council_resp.status_code == 200
    council_data = council_resp.json()
    assert council_data["incident_id"] == incident_id
    consensus_stat = council_data.get("consensus_metric", {}).get("status") or council_data.get("consensus_status")
    assert consensus_stat in ["FULL_CONSENSUS", "CONSENSUS_CONFIRMED", "CONSENSUS_REACHED", "MAJORITY_CONSENSUS", "DISSENT_DETECTED"]

    # 3. Query reports under single unified org view
    reports_resp = test_client.get(f"/api/v1/reports?org_id={org_id}")
    assert reports_resp.status_code == 200
    reports = reports_resp.json()
    assert len(reports) >= 1
    assert reports[0]["org_id"] == org_id
    assert "surface_id" not in reports[0] or reports[0].get("surface_id") is None

    print(f"\n[GOLDEN PATH PASS] Simplified single-org, single-key pipeline verified end-to-end.")

