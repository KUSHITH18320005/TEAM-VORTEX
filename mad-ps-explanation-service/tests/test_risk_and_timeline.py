"""
Unit tests for Deterministic Risk Scoring (Task D1) and Grounded Timeline (Task D2).
"""

import asyncio
import os
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from schemas.incident import IncidentRecord, TimelineEvent
from schemas.report import ReconstructionResult
from scoring.risk_calculator import RiskCalculator
from timeline.correlator import TimelineCorrelator


def create_isolated_sqli_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-SQLI-01",
        timestamp="2026-09-04T12:00:00Z",
        category="SQLi",
        severity="CRITICAL",
        confidence=0.90,
        contributing_branch_scores={"semantic": 0.95},
        raw_log_details={
            "endpoint": "/api/v1/search",
            "method": "POST",
            "status_code": 500,
            "source_ip": "203.0.113.19",
        },
        campaign_id=None,  # Isolated
        timeline_events=[],
    )


def create_campaign_idor_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-IDOR-CAMP-01",
        timestamp="2026-09-04T12:05:00Z",
        category="IDOR",
        severity="HIGH",
        confidence=0.85,
        contributing_branch_scores={"semantic": 0.90},
        raw_log_details={
            "endpoint": "/api/v1/user/1042/profile",
            "method": "GET",
            "status_code": 200,
            "source_ip": "198.51.100.42",
        },
        campaign_id="CAMP-ALPHA-77",  # Multi-stage campaign
        timeline_events=[
            TimelineEvent(
                timestamp="2026-09-04T12:00:00Z",
                action="POST /api/v1/auth/login",
                source_ip="198.51.100.42",
                status_code=200,
            ),
            TimelineEvent(
                timestamp="2026-09-04T12:02:00Z",
                action="GET /api/v1/user/search?q=admin",
                source_ip="198.51.100.42",
                status_code=200,
            ),
            TimelineEvent(
                timestamp="2026-09-04T12:05:00Z",
                action="GET /api/v1/user/1042/profile",
                source_ip="198.51.100.42",
                status_code=200,
                payload_summary="Extracted unowned profile",
            ),
        ],
    )


def test_risk_calculator_isolated_incident():
    incident = create_isolated_sqli_incident()
    assessment = RiskCalculator.calculate_risk(incident)

    # Base severity for SQLi is 9.0, Confidence is 0.90 -> 9.0 * 0.90 = 8.10
    # Isolated -> campaign_boost = 0.0 -> Score = 8.10 (HIGH)
    assert assessment.base_severity == 9.0
    assert assessment.mesh_confidence == 0.90
    assert assessment.is_campaign is False
    assert assessment.campaign_boost == 0.0
    assert assessment.score == 8.10
    assert assessment.severity_band == "HIGH"
    assert "RiskScore = min(10.0" in assessment.formula


def test_risk_calculator_campaign_boost():
    incident = create_campaign_idor_incident()
    assessment = RiskCalculator.calculate_risk(incident)

    # Base severity for IDOR is 8.0, Confidence is 0.85 -> 8.0 * 0.85 = 6.80
    # Campaign with 3 events -> campaign_boost = 1.0 + (3-1)*0.25 = 1.50
    # Raw Score = 6.80 + 1.50 = 8.30 (HIGH)
    assert assessment.base_severity == 8.0
    assert assessment.mesh_confidence == 0.85
    assert assessment.is_campaign is True
    assert assessment.campaign_id == "CAMP-ALPHA-77"
    assert assessment.campaign_boost == 1.50
    assert assessment.score == 8.30
    assert assessment.severity_band == "HIGH"


def test_timeline_correlator_with_events():
    incident = create_campaign_idor_incident()
    mock_recon = ReconstructionResult(
        incident_id=incident.incident_id,
        entry_point="POST /api/v1/auth/login",
        attack_sequence=[
            "Step 1: Attacker authenticated with valid credentials.",
            "Step 2: Attacker probed the user search endpoint to identify targets.",
            "Step 3: Attacker exploited IDOR flaw by requesting target user 1042 profile.",
        ],
        underlying_condition="Broken Object Level Authorization",
        grounded_evidence_fields=["endpoint", "status_code"],
    )

    timeline = TimelineCorrelator.build_grounded_timeline(incident, mock_recon)

    assert timeline.incident_id == incident.incident_id
    assert timeline.campaign_id == "CAMP-ALPHA-77"
    assert timeline.total_events == 3
    assert timeline.time_span_seconds == 300.0  # 12:00:00 to 12:05:00 = 5 min = 300s

    # Verify chronological ordering & annotations
    assert timeline.entries[0].step_number == 1
    assert "login" in timeline.entries[0].action.lower()
    assert timeline.entries[0].stage == "RECONNAISSANCE"
    assert timeline.entries[0].narration == mock_recon.attack_sequence[0]
    assert timeline.entries[0].is_grounded_telemetry is True

    assert timeline.entries[1].step_number == 2
    assert "search" in timeline.entries[1].action.lower()

    assert timeline.entries[2].step_number == 3
    assert "1042" in timeline.entries[2].action
    assert timeline.entries[2].stage == "DATA_ACCESS"
    assert timeline.entries[2].narration == mock_recon.attack_sequence[2]


def test_timeline_correlator_fallback_single_log():
    incident = create_isolated_sqli_incident()
    mock_recon = ReconstructionResult(
        incident_id=incident.incident_id,
        entry_point="POST /api/v1/search",
        attack_sequence=["Single SQL injection payload delivered to search route."],
        underlying_condition="SQL Injection in search controller",
        grounded_evidence_fields=["raw_logs"],
    )

    timeline = TimelineCorrelator.build_grounded_timeline(incident, mock_recon)

    assert timeline.total_events == 1
    assert timeline.time_span_seconds == 0.0
    assert timeline.entries[0].endpoint == "/api/v1/search"
    assert timeline.entries[0].status_code == 500
    assert timeline.entries[0].is_grounded_telemetry is True


if __name__ == "__main__":
    test_risk_calculator_isolated_incident()
    test_risk_calculator_campaign_boost()
    test_timeline_correlator_with_events()
    test_timeline_correlator_fallback_single_log()
    print("All Risk and Timeline unit tests passed successfully!")
