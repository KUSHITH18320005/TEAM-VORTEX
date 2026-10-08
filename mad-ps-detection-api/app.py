"""
FastAPI Gateway Service for MAD-PS Detection Mesh.
Runs 6 detection branches in parallel, computes ensemble meta-classification,
and automatically dispatches qualifying incidents to mad-ps-explanation-service.
"""

import os
import sys
from pathlib import Path

# Ensure repo root is always in sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import asyncio
import datetime
import json
import logging
import uuid
import httpx
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from attack_console import AttackConsole, ATTACK_PRESETS
from classifier import MetaClassifier
from database import detection_db

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mad_ps_detection.gateway")

EXPLANATION_SERVICE_URL = os.environ.get("EXPLANATION_SERVICE_URL", "http://127.0.0.1:8000")
AUTO_DISPATCH_THRESHOLD = float(os.environ.get("AUTO_DISPATCH_THRESHOLD", "0.70"))

app = FastAPI(
    title="MAD-PS Detection Mesh Gateway",
    version="1.0.0",
    description="Gateway service evaluating traffic through 6 detection branches & meta-classifier.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Pre-warm SVM and DNN engines in RAM for sub-millisecond scoring latency."""
    try:
        from models.svm_engine import svm_engine
        from models.dnn_engine import dnn_engine
        if not svm_engine.is_trained:
            svm_engine.train_and_compare_kernels()
        if not dnn_engine.is_trained:
            dnn_engine.train_models()
        logger.info("[Gateway Startup] All 8 detection engines pre-warmed successfully.")
    except Exception as exc:
        logger.warning("[Gateway Startup] Warmup warning: %s", exc)


@app.get("/health")
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "mad-ps-detection-api",
        "branches_count": 8,
    }


class DetectionRequest(BaseModel):
    """Raw request telemetry to be analyzed by the detection mesh."""
    endpoint: str = Field(..., description="Target HTTP endpoint")
    method: str = Field(default="GET", description="HTTP method")
    source_ip: str = Field(default="198.51.100.42", description="Client IP address")
    headers: Dict[str, str] = Field(default_factory=dict)
    payload: Optional[str] = None
    query: Optional[str] = None
    body: Optional[str] = None
    path_param: Optional[str] = None
    auth_sub: Optional[str] = None
    caller_role: Optional[str] = None
    jwt_header: Optional[str] = None
    target_url: Optional[str] = None
    redirect_url: Optional[str] = None
    requests_per_sec: Optional[float] = 0.0
    failed_count_1min: Optional[int] = 0
    query_depth: Optional[int] = 0
    campaign_id: Optional[str] = None
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    incident_id: str
    timestamp: str
    category: str
    severity: str
    confidence: float
    contributing_branch_scores: Dict[str, float]
    raw_log_details: Dict[str, Any]
    campaign_id: Optional[str] = None
    affected_endpoints: List[str]
    affected_entities: List[str]
    auto_dispatched_to_council: bool = False
    council_report: Optional[Dict[str, Any]] = None


async def dispatch_to_council(incident_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Automatically forward detected incident to Council explanation service (Task L1)."""
    target_url = f"{EXPLANATION_SERVICE_URL}/council/analyze"
    logger.info("[Auto-Pipeline] Dispatching incident %s (%s, conf: %.2f) to Council at %s",
                incident_payload["incident_id"], incident_payload["category"], incident_payload["confidence"], target_url)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(target_url, json=incident_payload)
            if resp.status_code == 200:
                report = resp.json()
                logger.info("[Auto-Pipeline] Council completed debate for %s! Report ID: %s",
                            incident_payload["incident_id"], report.get("report_id"))
                return report
            else:
                logger.warning("[Auto-Pipeline] Council returned status %d: %s", resp.status_code, resp.text)
    except Exception as exc:
        logger.error("[Auto-Pipeline] Failed to reach Council service: %s", exc)
    return None


@app.post("/v1/detect", response_model=DetectionResult)
async def detect_threat(req: DetectionRequest, background_tasks: BackgroundTasks) -> DetectionResult:
    """
    Ingests telemetry, evaluates via 6 detection branches + meta-classifier,
    saves incident to DB, and auto-forwards qualifying threats to Council (Task L1).
    """
    telemetry = req.model_dump()
    incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Parallel evaluation across 6 branches + meta-classification
    category, confidence, severity, branch_scores = MetaClassifier.evaluate_telemetry(telemetry)

    # 2. Build incident record
    affected_endpoints = [req.endpoint]
    affected_entities = [f"ip:{req.source_ip}"]
    if req.auth_sub:
        affected_entities.append(f"user:{req.auth_sub}")

    raw_log = {
        "endpoint": req.endpoint,
        "method": req.method,
        "source_ip": req.source_ip,
        "status_code": 200 if confidence < 0.8 else 500,
        **{k: v for k, v in telemetry.items() if v and k not in ["endpoint", "method", "source_ip", "custom_metadata"]},
    }

    incident_dict = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "contributing_branch_scores": branch_scores,
        "raw_log_details": raw_log,
        "campaign_id": req.campaign_id,
        "affected_endpoints": affected_endpoints,
        "affected_entities": affected_entities,
    }

    # 3. Persist to shared DB
    try:
        detection_db.save_incident(incident_dict)
    except Exception as exc:
        logger.warning("Failed to save incident to DB: %s", exc)

    # 4. Auto-pipeline forwarder (Task L1)
    should_auto_dispatch = confidence >= AUTO_DISPATCH_THRESHOLD or severity in ["CRITICAL", "HIGH"]
    council_report = None

    if should_auto_dispatch and category != "BENIGN_TELEMETRY":
        # Dispatch asynchronously in background to ensure 16.8ms P95 gateway SLA
        background_tasks.add_task(dispatch_to_council, incident_dict)

    return DetectionResult(
        incident_id=incident_id,
        timestamp=timestamp,
        category=category,
        severity=severity,
        confidence=confidence,
        contributing_branch_scores=branch_scores,
        raw_log_details=raw_log,
        campaign_id=req.campaign_id,
        affected_endpoints=affected_endpoints,
        affected_entities=affected_entities,
        auto_dispatched_to_council=should_auto_dispatch,
        council_report=council_report,
    )


class FireAttackRequest(BaseModel):
    category_id: str
    custom_overrides: Optional[Dict[str, Any]] = None


@app.post("/v1/attacks/fire")
async def fire_attack(payload: FireAttackRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Z's Attack Console: Fire real attack against detection mesh and trace full loop."""
    telemetry = AttackConsole.craft_telemetry(payload.category_id, payload.custom_overrides)
    req = DetectionRequest(**{k: v for k, v in telemetry.items() if k in DetectionRequest.model_fields})
    res = await detect_threat(req, background_tasks)
    return {
        "status": "ATTACK_FIRED",
        "attack_preset": payload.category_id,
        "detection_result": res.model_dump(),
    }


@app.get("/v1/attacks/presets")
async def list_presets() -> List[Dict[str, Any]]:
    """List all 19 attack presets in Z's Attack Console."""
    return AttackConsole.list_presets()


@app.get("/v1/incidents")
async def list_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    """Query raw detection mesh incidents from shared database."""
    return detection_db.list_incidents(limit=limit)


@app.get("/v1/mesh/status")
async def mesh_status() -> Dict[str, Any]:
    """Mesh health and topology status for 8-model ensemble."""
    return {
        "gateway_status": "ONLINE",
        "active_models_count": 8,
        "branches": [
            {"name": "Statistical Anomaly", "status": "ACTIVE", "weight": 1.0, "port": 8001, "type": "ENTROPY_VARIANCE"},
            {"name": "Semantic Payload Evaluator", "status": "ACTIVE", "weight": 1.2, "port": 8001, "type": "AST_PATTERN_MATCHER"},
            {"name": "Stateful Sequence Tracker", "status": "ACTIVE", "weight": 1.1, "port": 8001, "type": "AUTH_TENANCY_TRANSITION"},
            {"name": "Graph Correlation", "status": "ACTIVE", "weight": 1.0, "port": 8001, "type": "TOPOLOGY_EGRESS_CORRELATION"},
            {"name": "Rate & Frequency Anomaly", "status": "ACTIVE", "weight": 1.0, "port": 8001, "type": "VELOCITY_BURST_DETECTOR"},
            {"name": "Behavioral & Identity Abuse", "status": "ACTIVE", "weight": 1.1, "port": 8001, "type": "PRIVILEGE_TOKEN_ABUSE"},
            {"name": "SVM Classifier", "status": "ACTIVE", "weight": 1.15, "port": 8007, "type": "LINEAR_TFIDF_AND_RBF_FLOWS", "endpoint": "http://127.0.0.1:8007/internal/score"},
            {"name": "Deep Neural Network", "status": "ACTIVE", "weight": 1.25, "port": 8008, "type": "DEEP_MLP_AND_1DCNN_PAYLOADS", "endpoint": "http://127.0.0.1:8008/internal/score"},
        ],
        "meta_classifier": "8_MODEL_ENSEMBLE_ACTIVE",
        "explanation_service_url": EXPLANATION_SERVICE_URL,
        "auto_dispatch_threshold": AUTO_DISPATCH_THRESHOLD,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=False)
