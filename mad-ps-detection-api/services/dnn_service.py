"""
Deep Neural Network Service for MAD-PS Detection Mesh (Port 8008).
Hosts M2a Deep MLP (flow/behavioral) and M2b Multi-Kernel 1D-CNN (character-level payload sequences).
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root is in sys.path
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.dnn_engine import dnn_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mad_ps.dnn_service")

app = FastAPI(
    title="MAD-PS Deep Neural Network Scoring Service",
    version="1.0.0",
    description="Dual-branch Deep Learning service: M2a Deep MLP (4 layers + BatchNorm + Dropout) & M2b 1D-CNN (multi-scale kernels 3/5/7).",
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
    logger.info("Initializing DNN Engine and training deep models...")
    dnn_engine.train_models()
    logger.info("DNN Engine initialized successfully.")


@app.get("/health")
@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "dnn-service",
        "port": 8008,
        "is_trained": dnn_engine.is_trained,
        "branches": ["M2a_Deep_MLP", "M2b_Payload_1DCNN"],
    }


@app.get("/status")
@app.get("/api/v1/status")
async def service_status() -> Dict[str, Any]:
    return {
        "service": "dnn-service",
        "port": 8008,
        "m2a_mlp_architecture": "input -> Linear(256) -> BatchNorm1d -> ReLU -> Dropout(0.3) -> Linear(128) -> BatchNorm1d -> ReLU -> Dropout(0.3) -> Linear(64) -> BatchNorm1d -> ReLU -> Dropout(0.3) -> Linear(32) -> BatchNorm1d -> ReLU -> Linear(classes) -> Softmax",
        "m2b_1dcnn_architecture": "Embedding(vocab=128, dim=64) -> Parallel Conv1D(k=3, 5, 7) -> GlobalMaxPooling1D -> Dense(64) -> Dropout(0.3) -> Dense(classes) -> Softmax",
        "novelty_citation": "Payload-level 1D-CNN with parallel multi-scale kernels (3/5/7) for obfuscated/polyglot injection detection beyond standard token bags.",
    }


@app.post("/internal/score")
@app.post("/api/v1/score")
async def internal_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Routes telemetry to M2a (flow/behavioral) or M2b (payload sequences) and returns calibrated score.
    """
    try:
        res = dnn_engine.score_telemetry(payload)
        return res
    except Exception as exc:
        logger.error("DNN scoring failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("services.dnn_service:app", host="0.0.0.0", port=8008, reload=False)
