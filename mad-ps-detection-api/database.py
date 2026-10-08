"""
Shared Database Client for mad-ps-detection-api.
Reads and writes incidents and reports to the shared PostgreSQL / SQLite database.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mad_ps_detection.database")

DB_DIR = Path(os.environ.get("MAD_PS_DATA_DIR", "../data"))
if not DB_DIR.exists() and Path("./data").exists():
    DB_DIR = Path("./data")
DB_FILE = DB_DIR / "mad_ps_product.db"


class DetectionDatabase:
    """Manages persistent storage for detection mesh incidents and query integration."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = Path(db_path or DB_FILE)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Ensure schema exists."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    contributing_branch_scores TEXT,
                    raw_log_details TEXT,
                    campaign_id TEXT,
                    affected_endpoints TEXT,
                    affected_entities TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_reports (
                    report_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    executive_summary TEXT NOT NULL,
                    incident_category TEXT NOT NULL,
                    detection_mesh_confidence REAL NOT NULL,
                    consensus_status TEXT NOT NULL,
                    consensus_score REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_severity_band TEXT NOT NULL,
                    requires_human_approval INTEGER NOT NULL,
                    human_approval_reasoning TEXT,
                    root_cause TEXT NOT NULL,
                    technical_timeline TEXT,
                    ranked_actions TEXT,
                    reconstruction_findings TEXT,
                    response_plan TEXT,
                    judge_synthesis TEXT,
                    debate_revisions TEXT,
                    risk_assessment TEXT,
                    grounded_timeline TEXT,
                    participating_models TEXT,
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
                )
            """)
            conn.commit()

    def save_incident(self, incident: Dict[str, Any]) -> None:
        """Save a new detection incident."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, timestamp, category, severity, confidence,
                    contributing_branch_scores, raw_log_details, campaign_id,
                    affected_endpoints, affected_entities, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.get("incident_id"),
                incident.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                incident.get("category", "UNKNOWN"),
                incident.get("severity", "MEDIUM"),
                float(incident.get("confidence", 0.0)),
                json.dumps(incident.get("contributing_branch_scores", {})),
                json.dumps(incident.get("raw_log_details", {})),
                incident.get("campaign_id"),
                json.dumps(incident.get("affected_endpoints", [])),
                json.dumps(incident.get("affected_entities", [])),
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
            ))
            conn.commit()

    def list_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent raw incidents."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "incident_id": r["incident_id"],
                    "timestamp": r["timestamp"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "confidence": r["confidence"],
                    "contributing_branch_scores": json.loads(r["contributing_branch_scores"] or "{}"),
                    "raw_log_details": json.loads(r["raw_log_details"] or "{}"),
                    "campaign_id": r["campaign_id"],
                    "affected_endpoints": json.loads(r["affected_endpoints"] or "[]"),
                    "affected_entities": json.loads(r["affected_entities"] or "[]"),
                })
            return results


detection_db = DetectionDatabase()
shared_db = detection_db
