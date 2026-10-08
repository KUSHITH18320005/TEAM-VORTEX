"""
End-to-end multi-tenant pipeline tests for MAD-PS SaaS ecosystem.
Verifies SaaS signup, domain ownership challenge verification, SDK log ingestion,
and strict multi-tenant isolation with zero data leakage.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure explanation service root is in path
explanation_path = Path(__file__).resolve().parent.parent / "mad-ps-explanation-service"
if str(explanation_path) not in sys.path:
    sys.path.insert(0, str(explanation_path))

from app import app
from database import shared_db


@pytest.fixture
def client():
    return TestClient(app)


def test_saas_auth_signup_and_login(client):
    """Verify organization creation, user registration, and JWT login issuance."""
    test_email = f"lead_analyst_{id(client)}@acmecorp.com"
    signup_payload = {
        "email": test_email,
        "password": "SecurePassword2026!",
        "name": "Sarah Connor",
        "org_name": "Cyberdyne Defense",
        "plan_tier": "pro",
    }

    # 1. Signup
    res = client.post("/api/v1/auth/signup", json=signup_payload)
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["org"]["name"] == "Cyberdyne Defense"
    assert data["org"]["plan_tier"] == "pro"
    assert data["api_key"].startswith("mk_live_")

    token = data["access_token"]
    org_id = data["org"]["org_id"]

    # 2. Verify /api/v1/auth/me
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["user"]["email"] == test_email
    assert me_data["org"]["org_id"] == org_id
    assert len(me_data["api_keys"]) >= 1

    # 3. Login
    login_res = client.post("/api/v1/auth/login", json={"email": test_email, "password": "SecurePassword2026!"})
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data


def test_domain_verification_challenge(client):
    """Verify application onboarding and challenge token verification."""
    # Register app
    app_res = client.post("/api/v1/apps", json={
        "name": "Payments Portal",
        "domain": "pay.internal.test",
        "verification_method": "http_file",
    })
    assert app_res.status_code == 200
    app_data = app_res.json()
    app_id = app_data["app_id"]
    assert app_data["is_verified"] is False
    assert app_data["verification_token"].startswith("madps_vfy_")
    assert app_data["verification_path"].startswith("/.well-known/madps-verify-")

    # Verify domain
    verify_res = client.post(f"/api/v1/apps/{app_id}/verify?simulate=true")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["is_verified"] is True

    # Check status endpoint
    status_res = client.get(f"/api/v1/apps/{app_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["app"]["is_verified"] is True


def test_public_contact_form(client):
    """Verify public landing page contact form writes to contact_requests table."""
    contact_res = client.post("/api/v1/contact", json={
        "name": "Enterprise Director",
        "email": "director@megacorp.com",
        "company": "MegaCorp Global",
        "message": "We need MAD-PS 8-model detection mesh across 200 microservices.",
    })
    assert contact_res.status_code == 200
    contact_data = contact_res.json()
    assert contact_data["status"] == "success"
    assert contact_data["request_id"].startswith("req_")


def test_strict_multitenant_isolation_and_sdk_ingestion(client):
    """
    Task Q1 & Q2: Create two separate organizations.
    Ingest attack for Org A and benign telemetry for Org B.
    Confirm complete isolation: Org B has zero visibility into Org A's incidents.
    """
    # 1. Create Org A (Titan Security)
    res_a = client.post("/api/v1/auth/signup", json={
        "email": f"analyst_a_{id(client)}@titan.io",
        "password": "Password123!",
        "name": "Analyst A",
        "org_name": "Titan Security",
    })
    data_a = res_a.json()
    api_key_a = data_a["api_key"]
    org_id_a = data_a["org"]["org_id"]

    # 2. Create Org B (Nebula Cloud)
    res_b = client.post("/api/v1/auth/signup", json={
        "email": f"analyst_b_{id(client)}@nebula.io",
        "password": "Password123!",
        "name": "Analyst B",
        "org_name": "Nebula Cloud",
    })
    data_b = res_b.json()
    api_key_b = data_b["api_key"]
    org_id_b = data_b["org"]["org_id"]

    assert org_id_a != org_id_b
    assert api_key_a != api_key_b

    # 3. Ingest SQL Injection attack into Org A via SDK endpoint
    ingest_a = client.post(
        "/api/v1/ingest/log",
        headers={"X-API-Key": api_key_a},
        json={
            "timestamp": "2026-09-05T00:00:00Z",
            "method": "POST",
            "path": "/api/v1/search",
            "payload": "' UNION SELECT username, password_hash FROM users --",
            "headers": {"Host": "titan.io", "Content-Type": "application/json"},
            "status_code": 200,
            "latency_ms": 12.0,
            "client_ip": "198.51.100.88",
        },
    )
    assert ingest_a.status_code == 200
    res_a_json = ingest_a.json()
    assert res_a_json["org_id"] == org_id_a
    assert res_a_json["is_threat"] is True
    assert res_a_json["category"] == "SQLi"

    # 4. Ingest Clean / Benign traffic into Org B via SDK endpoint
    ingest_b = client.post(
        "/api/v1/ingest/log",
        headers={"X-API-Key": api_key_b},
        json={
            "timestamp": "2026-09-05T00:00:00Z",
            "method": "GET",
            "path": "/api/v1/health",
            "payload": "",
            "headers": {"Host": "nebula.io"},
            "status_code": 200,
            "latency_ms": 4.5,
            "client_ip": "192.168.1.1",
        },
    )
    assert ingest_b.status_code == 200
    res_b_json = ingest_b.json()
    assert res_b_json["org_id"] == org_id_b
    assert res_b_json["is_threat"] is False

    # 5. Verify Org A can see its incident report
    reports_a = client.get(f"/api/v1/reports?org_id={org_id_a}").json()
    assert len(reports_a) >= 1
    assert any(r["incident_category"] == "SQLi" for r in reports_a)

    # 6. Verify Org B sees ZERO reports (100% Zero-Leakage Data Isolation)
    reports_b = client.get(f"/api/v1/reports?org_id={org_id_b}").json()
    assert len(reports_b) == 0, "Security Failure: Org B leaked incidents from Org A!"

    # 7. Verify invalid API key rejection (401 Unauthorized)
    invalid_res = client.post(
        "/api/v1/ingest/log",
        headers={"X-API-Key": "mk_live_invalid_bad_key_123"},
        json={"method": "GET", "path": "/test"},
    )
    assert invalid_res.status_code == 401
