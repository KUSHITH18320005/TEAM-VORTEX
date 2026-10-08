"""
Decision Manager for Human-in-the-Loop Action Authorizations (Task E2).
Maintains audit trail of all approved, rejected, or modified remediation steps.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from schemas.decision import ActionDecision, DecisionType

logger = logging.getLogger("mad_ps_explanation.decisions")


class DecisionManager:
    """Manages human approval workflows and action audit logs."""

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self.data_dir = Path(data_dir or os.environ.get("DECISIONS_DATA_DIR", "./data/decisions"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.decisions_file = self.data_dir / "action_decisions.jsonl"
        self._decisions: Dict[str, ActionDecision] = {}
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load decisions history from disk."""
        if self.decisions_file.exists():
            try:
                with open(self.decisions_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            dec = ActionDecision(**data)
                            self._decisions[dec.decision_id] = dec
            except Exception as exc:
                logger.warning("Failed to load decisions from %s: %s", self.decisions_file, exc)

    def record_decision(
        self,
        incident_id: str,
        report_id: str,
        action_id: str,
        decision: DecisionType,
        action_title: str,
        target_component: str,
        priority: str,
        analyst_id: str = "soc_lead",
        comments: Optional[str] = None,
        modification_details: Optional[str] = None,
    ) -> ActionDecision:
        """Log a human analyst decision and record execution readiness."""
        decision_record = ActionDecision(
            decision_id=f"DEC-{uuid.uuid4().hex[:8]}",
            incident_id=incident_id,
            report_id=report_id,
            action_id=action_id,
            decision=decision,
            analyst_id=analyst_id,
            action_title=action_title,
            target_component=target_component,
            priority=priority,
            comments=comments,
            modification_details=modification_details,
            execution_triggered=(decision == DecisionType.APPROVED),
            execution_status="EXECUTED_LOCAL_STUB" if decision == DecisionType.APPROVED else "ABORTED",
        )

        self._decisions[decision_record.decision_id] = decision_record
        self._append_to_disk(decision_record)

        logger.info(
            "Human Decision Logged: %s by %s on Action %s (%s) -> %s",
            decision_record.decision_id,
            analyst_id,
            action_id,
            action_title,
            decision.value,
        )
        return decision_record

    def _append_to_disk(self, record: ActionDecision) -> None:
        """Append record to JSONL."""
        try:
            with open(self.decisions_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.model_dump()) + "\n")
        except Exception as exc:
            logger.error("Failed to append decision to disk: %s", exc)

    def list_decisions(self, incident_id: Optional[str] = None, limit: Optional[int] = None) -> List[ActionDecision]:
        """List all logged human decisions optionally filtered by incident and limited."""
        all_decs = list(self._decisions.values())
        if incident_id:
            all_decs = [d for d in all_decs if d.incident_id == incident_id]
        res = sorted(all_decs, key=lambda d: d.timestamp, reverse=True)
        if limit is not None and limit > 0:
            return res[:limit]
        return res
