"""
Telemetry-Grounded Timeline Correlator (Task D2).
Aggregates real log events across campaign/incident timelines, sorts them chronologically,
and layers Agent 1 reconstruction narration directly onto verifiable telemetry records.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional
from schemas.incident import IncidentRecord, TimelineEvent
from schemas.report import ReconstructionResult
from schemas.timeline import AnnotatedTimelineEntry, GroundedTimeline

logger = logging.getLogger("mad_ps_explanation.timeline")


class TimelineCorrelator:
    """Builds verified chronological attack timelines enriched with LLM narration."""

    @classmethod
    def build_grounded_timeline(
        cls,
        incident: IncidentRecord,
        reconstruction: Optional[ReconstructionResult] = None,
        supplemental_logs: Optional[List[Dict[str, Any]]] = None,
    ) -> GroundedTimeline:
        """
        Assemble and annotate verified chronological attack timeline.
        Grounded strictly in real log entries with LLM narrative layering.
        """
        raw_events: List[Dict[str, Any]] = []

        # 1. Ingest incident timeline events
        if incident.timeline_events:
            for ev in incident.timeline_events:
                raw_events.append({
                    "timestamp": ev.timestamp,
                    "action": ev.action,
                    "source_ip": ev.source_ip or incident.source_ip or incident.raw_log_details.get("source_ip"),
                    "status_code": ev.status_code,
                    "endpoint": ev.metadata.get("endpoint") or ev.action.split(" ")[-1] if " " in ev.action else None,
                    "payload_summary": ev.payload_summary,
                    "raw_data": ev.metadata or {"action": ev.action, "user_id": ev.user_id},
                })

        # 2. Ingest supplemental campaign logs if provided
        if supplemental_logs:
            for log in supplemental_logs:
                raw_events.append({
                    "timestamp": log.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                    "action": log.get("action", f"{log.get('method', 'GET')} {log.get('endpoint', '/')}") ,
                    "source_ip": log.get("source_ip") or log.get("ip"),
                    "status_code": log.get("status_code"),
                    "endpoint": log.get("endpoint"),
                    "payload_summary": log.get("payload_summary") or log.get("payload_snippet"),
                    "raw_data": log,
                })

        # 3. If no timeline events exist, fallback to single raw log entry
        if not raw_events:
            raw_events.append({
                "timestamp": incident.timestamp,
                "action": f"{incident.raw_log_details.get('method', 'HTTP')} {incident.raw_log_details.get('endpoint', incident.category)}",
                "source_ip": incident.source_ip or incident.raw_log_details.get("source_ip"),
                "status_code": incident.raw_log_details.get("status_code"),
                "endpoint": incident.raw_log_details.get("endpoint"),
                "payload_summary": incident.raw_log_details.get("payload_snippet") or incident.raw_log_details.get("payload_summary"),
                "raw_data": incident.raw_log_details,
            })

        # 4. Sort chronologically
        def _parse_ts(ts_str: str) -> float:
            try:
                # Replace trailing 'Z' if present
                clean = ts_str.replace("Z", "+00:00")
                return datetime.datetime.fromisoformat(clean).timestamp()
            except Exception:
                return 0.0

        sorted_events = sorted(raw_events, key=lambda e: _parse_ts(e.get("timestamp", "")))

        # Compute time span
        if len(sorted_events) > 1:
            t_first = _parse_ts(sorted_events[0].get("timestamp", ""))
            t_last = _parse_ts(sorted_events[-1].get("timestamp", ""))
            time_span = max(0.0, t_last - t_first)
        else:
            time_span = 0.0

        # 5. Layer Agent 1 narration onto each verified telemetry entry
        annotated_entries: List[AnnotatedTimelineEntry] = []
        recon_steps = (reconstruction.attack_sequence if reconstruction else None) or [incident.category]

        for idx, ev in enumerate(sorted_events, start=1):
            stage = cls._infer_stage(idx, len(sorted_events), ev)

            # Match or interpolate narration from Agent 1's reconstruction
            if idx <= len(recon_steps):
                narrative = recon_steps[idx - 1]
            elif idx == len(sorted_events):
                narrative = f"Detection mesh triggered alert on {ev.get('action')}. Threat scored at confidence {incident.confidence:.2f}."
            else:
                narrative = f"Attacker executed {ev.get('action')} resulting in HTTP status {ev.get('status_code') or 'observed'}."

            annotated_entries.append(AnnotatedTimelineEntry(
                step_number=idx,
                timestamp=ev.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                action=ev.get("action", "Unknown Action"),
                source_ip=ev.get("source_ip"),
                endpoint=ev.get("endpoint"),
                status_code=ev.get("status_code"),
                stage=stage,
                narration=narrative,
                is_grounded_telemetry=True,
                raw_log_ref=ev.get("raw_data", {}),
            ))

        return GroundedTimeline(
            incident_id=incident.incident_id,
            campaign_id=incident.campaign_id,
            total_events=len(annotated_entries),
            time_span_seconds=round(time_span, 2),
            entries=annotated_entries,
        )

    @classmethod
    def _infer_stage(cls, step: int, total: int, ev: Dict[str, Any]) -> str:
        """Categorize attack lifecycle stage from telemetry action and sequence index."""
        action = str(ev.get("action", "")).upper()
        status = ev.get("status_code")

        if step == 1 and ("LOGIN" in action or "AUTH" in action or step == 1 and total > 2):
            return "RECONNAISSANCE"
        if "PROBE" in action or "SEARCH" in action or step == 2 and total > 3:
            return "INITIAL_PROBE"
        if status in [200, 201] and ("USER" in action or "PROFILE" in action or "EXPORT" in action):
            return "DATA_ACCESS"
        if status == 500 or "INJECTION" in action or "EXPLOIT" in action or "SELECT" in action:
            return "EXPLOITATION"
        if step == total:
            return "DETECTION"
        return "EXPLOITATION"
