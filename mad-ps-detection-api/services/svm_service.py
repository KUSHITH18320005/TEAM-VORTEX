"""
SVM Service for MAD-PS Detection Mesh (Port 8007).
Provides high-performance SVM scoring with kernel competition results and verified StandardScaler.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.svm_engine import svm_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mad_ps.svm_service")

app = FastAPI(
    title="MAD-PS SVM Scoring Service",
    version="1.0.0",
    description="SVM classifier branch service with Linear vs RBF kernel optimization and StandardScaler.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    logger.info("Initializing SVM Engine and running kernel competition...")
    svm_engine.train_and_compare_kernels()
    logger.info("SVM Engine initialized successfully. Winning kernels: Web=%s, Net=%s",
                svm_engine.web_kernel_comparison.get("winning_kernel"),
                svm_engine.net_kernel_comparison.get("winning_kernel"))


@app.get("/health")
@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "svm-service",
        "port": 8007,
        "scaler_verified": svm_engine.is_scaler_verified,
        "is_trained": svm_engine.is_trained,
    }


@app.get("/status")
@app.get("/api/v1/status")
async def service_status() -> Dict[str, Any]:
    return {
        "service": "svm-service",
        "port": 8007,
        "scaler_verified": svm_engine.is_scaler_verified,
        "web_branch_comparison": svm_engine.web_kernel_comparison,
        "network_branch_comparison": svm_engine.net_kernel_comparison,
        "complexity_note": "SVC complexity is O(n^2)-O(n^3); Linear kernel selected for high-dimensional TF-IDF, RBF for network flows with stratified subsampling.",
    }


@app.post("/internal/score")
@app.post("/api/v1/score")
async def internal_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates telemetry through SVM engine and returns calibrated score.
    Matching standard branch-service contract.
    """
    try:
        res = svm_engine.score_telemetry(payload)
        return res
    except Exception as exc:
        logger.error("SVM scoring failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("services.svm_service:app", host="0.0.0.0", port=8007, reload=False)
