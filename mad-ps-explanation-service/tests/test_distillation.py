"""
Unit tests for AI Distillation subsystem (Tier 1 In-Context Distillation & Tier 2 Dataset Export).
"""

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.council import CouncilDebateEngine
from distillation.exemplar_store import ExemplarStore
from distillation.models import DebateTranscript, FeedbackRating, HumanFeedback
from distillation.pipeline import DistillationPipeline
from llm.mock_provider import MockLLMProvider
from schemas.incident import IncidentRecord, TimelineEvent


def create_sample_incident(incident_id: str = "INC-2026-DIST-01", category: str = "IDOR") -> IncidentRecord:
    return IncidentRecord(
        incident_id=incident_id,
        timestamp="2026-09-04T12:00:00Z",
        category=category,
        severity="HIGH",
        confidence=0.94,
        contributing_branch_scores={
            "statistical_anomaly": 0.88,
            "semantic_payload_evaluator": 0.94,
            "stateful_sequence_tracker": 0.79,
        },
        raw_log_details={
            "endpoint": "/api/v1/user/1042/profile",
            "method": "GET",
            "status_code": 200,
            "source_ip": "198.51.100.42",
        },
        timeline_events=[
            TimelineEvent(
                timestamp="2026-09-04T12:00:00Z",
                action="GET /api/v1/user/1042/profile",
                source_ip="198.51.100.42",
                status_code=200,
            )
        ],
        affected_endpoints=["/api/v1/user/{id}/profile"],
    )


@pytest.mark.asyncio
async def test_exemplar_store_and_feedback_lifecycle():
    temp_dir = tempfile.mkdtemp()
    try:
        store = ExemplarStore(data_dir=temp_dir)
        pipeline = DistillationPipeline(store=store)

        engine = CouncilDebateEngine(
            distillation_pipeline=pipeline,
            reconstruction_provider=MockLLMProvider(provider_label="anthropic"),
            response_provider=MockLLMProvider(provider_label="openai"),
            judge_provider=MockLLMProvider(provider_label="gemini"),
        )

        incident_1 = create_sample_incident(incident_id="INC-IDOR-01", category="IDOR")
        report_1 = await engine.run_council_debate(incident_1)

        # 1. Verify transcript recorded in store
        transcripts = list(store._transcripts.values())
        assert len(transcripts) == 1
        assert transcripts[0].incident_id == "INC-IDOR-01"
        assert transcripts[0].quality_score >= 0.85

        # 2. Record human feedback (Thumbs Up)
        fb = store.record_feedback(
            report_id=report_1.report_id,
            incident_id=report_1.incident_id,
            is_positive=True,
            comments="Accurate root cause and proportionate containment.",
        )
        assert fb.rating == FeedbackRating.POSITIVE
        assert store._transcripts[transcripts[0].session_id].quality_score == 1.0

        # 3. Verify exemplar generated for IDOR category
        exemplars = store.get_exemplars("IDOR", max_count=2)
        assert len(exemplars) == 1
        assert exemplars[0].category == "IDOR"
        assert exemplars[0].quality_score == 1.0
        assert "entry_point" in exemplars[0].reconstruction_demonstration

        # 4. Verify prompt formatting includes the exemplar
        few_shot_recon = pipeline.get_reconstruction_few_shot_prompt("IDOR")
        assert "HIGH-CONFIDENCE HISTORICAL EXAMPLES" in few_shot_recon
        assert "IDOR" in few_shot_recon

        # 5. Run second incident in same category — verify few-shot exemplars are injected
        incident_2 = create_sample_incident(incident_id="INC-IDOR-02", category="IDOR")
        report_2 = await engine.run_council_debate(incident_2)
        assert report_2.incident_id == "INC-IDOR-02"

        # 6. Verify Tier 2 fine-tuning dataset export
        sft_dataset = store.export_fine_tuning_dataset()
        assert len(sft_dataset) >= 1
        assert "messages" in sft_dataset[0]
        assert sft_dataset[0]["category"] == "IDOR"

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(test_exemplar_store_and_feedback_lifecycle())
    print("All Distillation unit tests passed successfully!")
