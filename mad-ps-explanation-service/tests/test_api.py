"""
Integration tests for FastAPI application endpoints.
"""

import asyncio
import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from schemas.incident import IncidentRecord


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "participating_models" in data


def test_analyze_incident_endpoint(client):
    incident_data = {
        "incident_id": "INC-2026-API-01",
        "category": "IDOR",
        "severity": "HIGH",
        "confidence": 0.91,
        "contributing_branch_scores": {"semantic": 0.95},
        "raw_log_details": {"endpoint": "/api/v1/user/1042/profile", "status_code": 200},
        "timeline_events": [],
    }
    payload = {
        "incident": incident_data,
        "supplemental_logs": None,
    }

    # Test Risk Score endpoint
    risk_resp = client.post("/api/v1/incidents/risk-score", json=incident_data)
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert risk_data["score"] > 0
    assert "formula" in risk_data

    # Test full analysis endpoint
    response = client.post("/api/v1/incidents/analyze", json=payload)
    assert response.status_code == 200
    report = response.json()
    assert report["incident_id"] == "INC-2026-API-01"
    assert "consensus_metric" in report
    assert "reconstruction_findings" in report
    assert "response_plan" in report
    assert "judge_synthesis" in report
    assert "debate_revisions" in report
    assert "risk_assessment" in report
    assert report["risk_assessment"]["score"] > 0
    assert "grounded_timeline" in report
    assert report["grounded_timeline"]["total_events"] >= 1

    # Test Human Feedback submission
    report_id = report["report_id"]
    fb_payload = {
        "incident_id": "INC-2026-API-01",
        "is_positive": True,
        "comments": "Accurate assessment confirmed by senior analyst",
    }
    fb_response = client.post(f"/api/v1/reports/{report_id}/feedback", json=fb_payload)
    assert fb_response.status_code == 200

    fb_data = fb_response.json()
    assert fb_data["rating"] == "POSITIVE"

    # Test Distillation Exemplars Endpoint
    ex_response = client.get("/api/v1/distillation/exemplars")
    assert ex_response.status_code == 200

    # Test Fine-Tuning Dataset Export Endpoint
    ds_response = client.get("/api/v1/distillation/dataset")
    assert ds_response.status_code == 200
    ds_data = ds_response.json()
    assert ds_data["count"] >= 1

    # Test Human Action Decision (Task E2)
    dec_payload = {
        "incident_id": "INC-2026-API-01",
        "report_id": report_id,
        "action_id": "ACT-01",
        "decision": "APPROVED",
        "action_title": "Invalidate Subject Token",
        "target_component": "Auth-Service",
        "priority": "P0_IMMEDIATE",
        "analyst_id": "soc_lead",
        "comments": "Approved for emergency containment",
    }
    dec_resp = client.post("/api/v1/decisions/action", json=dec_payload)
    assert dec_resp.status_code == 200
    dec_data = dec_resp.json()
    assert dec_data["decision"] == "APPROVED"
    assert dec_data["execution_triggered"] is True

    # Test Decision listing
    decs_list_resp = client.get("/api/v1/decisions")
    assert decs_list_resp.status_code == 200
    assert len(decs_list_resp.json()) >= 1

    # Test Sample Scenarios
    samples_resp = client.get("/api/v1/incidents/samples")
    assert samples_resp.status_code == 200
    assert len(samples_resp.json()) >= 3

    # Test Dashboard HTML Serving (Task E1)
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    assert "MADDY" in dash_resp.text

