"""
Deterministic Mathematical Risk Calculator (Task D1).
Computes a rigorous 0.0 - 10.0 risk score combining category base severity,
detection mesh confidence, and multi-stage campaign linkage.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple
from schemas.incident import IncidentRecord
from schemas.risk import RiskAssessment

logger = logging.getLogger("mad_ps_explanation.scoring")

# Documented Category Base-Severity Lookup Table
# Aligned with CVSS v3.1 / OWASP API Security Top 10 standards
CATEGORY_BASE_SEVERITY: Dict[str, float] = {
    # 10.0: Remote Code Execution / Complete System Compromise
    "RCE": 10.0,
    "COMMAND_INJECTION": 10.0,
    "REMOTE_CODE_EXECUTION": 10.0,

    # 9.0: Direct Data Exfiltration & Database Takeover
    "SQLI": 9.0,
    "SQL_INJECTION": 9.0,

    # 8.5: Server-Side Request Forgery / Internal Network Pivoting
    "SSRF": 8.5,
    "SERVER_SIDE_REQUEST_FORGERY": 8.5,

    # 8.0: Object-Level Authorization Bypass & Auth Bypass
    "IDOR": 8.0,
    "BOLA": 8.0,
    "BROKEN_OBJECT_LEVEL_AUTHORIZATION": 8.0,
    "BROKEN_AUTHENTICATION": 8.0,
    "JWT_TAMPERING": 8.0,
    "PRIVILEGE_ESCALATION": 8.0,

    # 7.0: Mass Assignment, Functional Auth Bypass, & Credential Attacks
    "MASS_ASSIGNMENT": 7.0,
    "BFLA": 7.0,
    "BROKEN_FUNCTION_LEVEL_AUTHORIZATION": 7.0,
    "CREDENTIAL_STUFFING": 7.0,
    "ACCOUNT_TAKEOVER": 7.0,

    # 6.5: API Token Misuse & Data Scraping
    "API_TOKEN_ABUSE": 6.5,
    "DATA_SCRAPING": 6.5,

    # 5.5: Resource Consumption & Rate Limit Evasion
    "RATE_LIMIT_BYPASS": 5.5,
    "API_ABUSE": 5.5,
    "DENIAL_OF_SERVICE": 5.5,

    # 5.0: Security Misconfiguration
    "SECURITY_MISCONFIGURATION": 5.0,
    "CORS_MISCONFIGURATION": 5.0,

    # 4.0: Information Disclosure
    "INFORMATION_DISCLOSURE": 4.0,
    "VERBOSE_ERROR": 4.0,
}

DEFAULT_BASE_SEVERITY = 5.0


class RiskCalculator:
    """Calculates deterministic, formulaic risk scores for security incidents."""

    @classmethod
    def get_base_severity(cls, category: str) -> float:
        """Lookup category base-severity with normalization."""
        norm = category.strip().upper().replace(" ", "_").replace("-", "_")
        return CATEGORY_BASE_SEVERITY.get(norm, DEFAULT_BASE_SEVERITY)

    @classmethod
    def calculate_risk(cls, incident: IncidentRecord) -> RiskAssessment:
        """
        Compute deterministic Risk Score (0.0 to 10.0).

        Mathematical Formula:
          Base Product   = Category Base Severity (0-10) * Mesh Confidence Score (0-1)
          Campaign Boost = min(2.0, 1.0 + 0.25 * (Linked Events - 1)) if campaign_id else 0.0
          Raw Score      = Base Product + Campaign Boost
          Final Score    = min(10.0, max(0.0, round(Raw Score, 2)))
        """
        base_sev = cls.get_base_severity(incident.category)
        mesh_conf = max(0.0, min(1.0, float(incident.confidence)))

        is_campaign = bool(incident.campaign_id and incident.campaign_id.strip())
        linked_count = len(incident.timeline_events) if incident.timeline_events else (1 if is_campaign else 0)

        # Multi-stage campaign boost: Multi-event distributed attacks carry greater operational threat
        if is_campaign:
            campaign_boost = min(2.0, round(1.0 + max(0, linked_count - 1) * 0.25, 2))
        else:
            campaign_boost = 0.0

        base_product = base_sev * mesh_conf
        raw_score = base_product + campaign_boost
        final_score = round(min(10.0, max(0.0, raw_score)), 2)

        # Assign severity band
        if final_score >= 9.0:
            severity_band = "CRITICAL"
        elif final_score >= 7.0:
            severity_band = "HIGH"
        elif final_score >= 4.0:
            severity_band = "MEDIUM"
        else:
            severity_band = "LOW"

        formula_str = (
            f"RiskScore = min(10.0, (BaseSeverity: {base_sev:.1f} × MeshConfidence: {mesh_conf:.2f}) "
            f"+ CampaignBoost: {campaign_boost:.2f}) = {final_score:.2f}"
        )

        campaign_desc = (
            f"Linked to Multi-Stage Campaign '{incident.campaign_id}' with {linked_count} correlated events (+{campaign_boost:.2f} risk boost)."
            if is_campaign else "Isolated single-stage incident (no campaign boost applied)."
        )

        explanation = (
            f"Category '{incident.category}' carries base severity {base_sev:.1f}/10.0. "
            f"Detection mesh meta-classifier returned {mesh_conf * 100:.1f}% confidence. "
            f"{campaign_desc} Resulting deterministic score is {final_score:.2f}/10.0 ({severity_band})."
        )

        return RiskAssessment(
            score=final_score,
            severity_band=severity_band,
            base_severity=base_sev,
            mesh_confidence=mesh_conf,
            is_campaign=is_campaign,
            campaign_id=incident.campaign_id,
            campaign_boost=campaign_boost,
            formula=formula_str,
            explanation=explanation,
        )
