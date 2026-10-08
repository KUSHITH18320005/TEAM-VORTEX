"""
Pydantic schemas for deterministic Risk Scoring (Task D1).
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class RiskAssessment(BaseModel):
    """
    Deterministic risk assessment computed via mathematical formula
    combining mesh confidence, category base-severity, and campaign correlation.
    """
    score: float = Field(..., ge=0.0, le=10.0, description="Risk score on a 0.0 to 10.0 scale")
    severity_band: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    base_severity: float = Field(..., description="Lookup base severity for the vulnerability category (0-10)")
    mesh_confidence: float = Field(..., description="Real meta-classifier confidence score from detection mesh (0-1)")
    is_campaign: bool = Field(..., description="Whether incident is linked to a multi-stage campaign")
    campaign_id: Optional[str] = Field(None, description="Campaign identifier if present")
    campaign_boost: float = Field(default=0.0, description="Additive boost applied for multi-stage campaign correlation")
    formula: str = Field(..., description="Human-readable mathematical expression used to derive the score")
    explanation: str = Field(..., description="Detailed breakdown of the mathematical risk computation")
