"""
Persistent store for debate transcripts, human analyst feedback, and category-indexed few-shot exemplars.
Supports in-context prompt distillation (Tier 1) and fine-tuning dataset generation (Tier 2).
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import DebateTranscript, FeedbackRating, FewShotExemplar, HumanFeedback

logger = logging.getLogger("mad_ps_explanation.distillation.store")


class ExemplarStore:
    """
    Manages persistent debate transcripts and extracts high-quality few-shot exemplars
    for automatic in-context distillation into Council prompts.
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self.data_dir = Path(data_dir or os.environ.get("DISTILLATION_DATA_DIR", "./data/distillation"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.transcripts_file = self.data_dir / "debate_transcripts.jsonl"
        self.feedback_file = self.data_dir / "human_feedback.json"
        self.exemplars_file = self.data_dir / "distilled_exemplars.json"

        # In-memory indices for rapid query
        self._transcripts: Dict[str, DebateTranscript] = {}
        self._feedbacks: Dict[str, HumanFeedback] = {}  # key: report_id
        self._exemplars_by_category: Dict[str, List[FewShotExemplar]] = {}

        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load transcripts, feedback, and exemplars from disk."""
        # Load feedback
        if self.feedback_file.exists():
            try:
                data = json.loads(self.feedback_file.read_text(encoding="utf-8"))
                for item in data:
                    fb = HumanFeedback(**item)
                    self._feedbacks[fb.report_id] = fb
            except Exception as exc:
                logger.warning("Failed to load feedback from %s: %s", self.feedback_file, exc)

        # Load transcripts
        if self.transcripts_file.exists():
            try:
                with open(self.transcripts_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            transcript = DebateTranscript(**data)
                            if transcript.final_report.report_id in self._feedbacks:
                                transcript.human_feedback = self._feedbacks[transcript.final_report.report_id]
                            transcript.quality_score = transcript.evaluate_quality()
                            self._transcripts[transcript.session_id] = transcript
            except Exception as exc:
                logger.warning("Failed to load transcripts from %s: %s", self.transcripts_file, exc)

        self._rebuild_exemplar_index()

    def _save_feedback_to_disk(self) -> None:
        """Persist feedback list to JSON file."""
        try:
            data = [fb.model_dump() for fb in self._feedbacks.values()]
            self.feedback_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write feedback to disk: %s", exc)

    def _append_transcript_to_disk(self, transcript: DebateTranscript) -> None:
        """Append a transcript to the JSONL log."""
        try:
            with open(self.transcripts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(transcript.model_dump()) + "\n")
        except Exception as exc:
            logger.error("Failed to append transcript to disk: %s", exc)

    def _save_exemplars_to_disk(self) -> None:
        """Persist compiled exemplars to JSON file."""
        try:
            all_exemplars = []
            for ex_list in self._exemplars_by_category.values():
                for ex in ex_list:
                    all_exemplars.append(ex.model_dump())
            self.exemplars_file.write_text(json.dumps(all_exemplars, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write exemplars to disk: %s", exc)

    def record_transcript(self, transcript: DebateTranscript) -> DebateTranscript:
        """Save a new debate transcript and update exemplar index."""
        transcript.quality_score = transcript.evaluate_quality()
        self._transcripts[transcript.session_id] = transcript
        self._append_transcript_to_disk(transcript)

        # Update exemplar index if high quality
        if transcript.quality_score >= 0.85:
            self._add_to_exemplars(transcript)
            self._save_exemplars_to_disk()

        logger.info(
            "Logged debate transcript %s (Incident: %s, Category: %s, Quality: %.2f)",
            transcript.session_id,
            transcript.incident_id,
            transcript.category,
            transcript.quality_score,
        )
        return transcript

    def record_feedback(
        self,
        report_id: str,
        incident_id: str,
        is_positive: bool,
        comments: Optional[str] = None,
        analyst_id: str = "soc_analyst",
    ) -> HumanFeedback:
        """Record a human thumbs-up / thumbs-down rating and re-evaluate transcript quality."""
        feedback = HumanFeedback(
            feedback_id=f"FB-{uuid.uuid4().hex[:8]}",
            report_id=report_id,
            incident_id=incident_id,
            rating=FeedbackRating.POSITIVE if is_positive else FeedbackRating.NEGATIVE,
            comments=comments,
            analyst_id=analyst_id,
        )
        self._feedbacks[report_id] = feedback
        self._save_feedback_to_disk()

        # Update associated transcript
        for t in self._transcripts.values():
            if t.final_report.report_id == report_id or t.incident_id == incident_id:
                t.human_feedback = feedback
                t.quality_score = t.evaluate_quality()
                break

        self._rebuild_exemplar_index()
        self._save_exemplars_to_disk()
        logger.info("Recorded feedback for report %s: %s", report_id, feedback.rating.value)
        return feedback

    def get_exemplars(self, category: str, max_count: int = 2) -> List[FewShotExemplar]:
        """
        Retrieve the top 2-3 category-matched distilled few-shot exemplars
        for dynamic prompt injection into Agent 1 / Agent 2.
        """
        norm_cat = category.strip().upper()
        candidates = self._exemplars_by_category.get(norm_cat, [])

        # Sort by quality score descending
        sorted_candidates = sorted(candidates, key=lambda x: x.quality_score, reverse=True)
        return sorted_candidates[:max_count]

    def _add_to_exemplars(self, t: DebateTranscript) -> None:
        """Convert a high-quality debate transcript into a distilled FewShotExemplar."""
        norm_cat = t.category.strip().upper()
        if norm_cat not in self._exemplars_by_category:
            self._exemplars_by_category[norm_cat] = []

        # Check if already indexed
        if any(e.source_incident_id == t.incident_id for e in self._exemplars_by_category[norm_cat]):
            return

        exemplar = FewShotExemplar(
            exemplar_id=f"EX-{t.category}-{uuid.uuid4().hex[:6]}",
            category=norm_cat,
            source_incident_id=t.incident_id,
            quality_score=t.quality_score,
            reconstruction_input_summary=f"Incident {t.incident_id} [{t.category}] - Mesh confidence: {t.incident_record.confidence:.2f}",
            reconstruction_demonstration={
                "entry_point": t.reconstruction_result.entry_point,
                "attack_sequence": t.reconstruction_result.attack_sequence,
                "underlying_condition": t.reconstruction_result.underlying_condition,
                "grounded_evidence_fields": t.reconstruction_result.grounded_evidence_fields,
            },
            response_input_summary=f"Reconstruction for {t.incident_id}: Root flaw: {t.reconstruction_result.underlying_condition}",
            response_demonstration={
                "immediate_containment": t.response_plan.immediate_containment,
                "architectural_prevention": t.response_plan.architectural_prevention,
                "requires_human_approval": t.response_plan.requires_human_approval,
                "human_approval_reasoning": t.response_plan.human_approval_reasoning,
            },
            judge_demonstration={
                "factuality_grounding_audit": t.judge_synthesis.factuality_grounding_audit,
                "proportionality_audit": t.judge_synthesis.proportionality_audit,
                "executive_summary": t.judge_synthesis.executive_summary,
                "root_cause_analysis": t.judge_synthesis.root_cause_analysis,
            },
        )
        self._exemplars_by_category[norm_cat].append(exemplar)

    def _rebuild_exemplar_index(self) -> None:
        """Re-scan all transcripts and compile the category-indexed exemplar set."""
        self._exemplars_by_category.clear()
        for t in self._transcripts.values():
            if t.quality_score >= 0.85:
                self._add_to_exemplars(t)

    def export_fine_tuning_dataset(self) -> List[Dict[str, Any]]:
        """
        Export SFT (Supervised Fine-Tuning) dataset for Tier 2 LoRA fine-tuning.
        Formats high-quality transcripts as prompt-completion pairs targeting the Judge synthesis.
        """
        dataset = []
        for t in self._transcripts.values():
            if t.quality_score >= 0.85:
                prompt = (
                    f"Incident: {t.incident_id} | Category: {t.category} | Severity: {t.incident_record.severity}\n"
                    f"Telemetry: {json.dumps(t.incident_record.raw_log_details)}\n"
                    f"Reconstruction: {t.reconstruction_result.underlying_condition}\n"
                    f"Response: {', '.join(t.response_plan.immediate_containment)}"
                )
                completion = json.dumps({
                    "executive_summary": t.judge_synthesis.executive_summary,
                    "root_cause_analysis": t.judge_synthesis.root_cause_analysis,
                    "ranked_actions": [a.model_dump() for a in t.judge_synthesis.ranked_actions],
                    "requires_human_approval": t.judge_synthesis.requires_human_approval,
                    "human_approval_justification": t.judge_synthesis.human_approval_justification,
                }, indent=2)

                dataset.append({
                    "id": f"sft-{t.incident_id}",
                    "messages": [
                        {"role": "system", "content": "You are the Supreme Judge and Chief Security Synthesizer for the MAD-PS SOC Council."},
                        {"role": "user", "content": prompt},
                        {"role": "assistant", "content": completion},
                    ],
                    "quality_score": t.quality_score,
                    "category": t.category,
                })
        return dataset
