"""
Unit & Integration Tests for Tasks L2 (Data Grounding Layer) & L3 (Conversation Memory).
Verifies:
1. Strict factual retrieval for incident records, SQL aggregate stats, mesh health, and Phase F benchmark metrics.
2. Mandatory citations attached to every grounded retrieval.
3. Explicit honest negative reporting when data does not exist (prevents LLM guessing).
4. Strict multi-tenant organizational isolation in conversation memory (Task L3).
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import SharedProductDatabase
from grounding.models import GroundingSourceType
from grounding.retriever import GroundingRetriever


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "test_product.db"
    db = SharedProductDatabase(db_path=str(db_path))
    return db


def test_grounding_incident_lookup(temp_db):
    retriever = GroundingRetriever(db=temp_db)

    # Insert sample incident report
    sample_report = {
        "report_id": "REP-SQLI-TEST-01",
        "incident_id": "INC-2026-SQLI-99",
        "org_id": "org_security_ops",
        "executive_summary": "SQL Injection attempt detected on /api/v1/search from IP 203.0.113.88.",
        "incident_category": "SQLi",
        "detection_mesh_confidence": 0.98,
        "consensus_metric": {"status": "FULL_CONSENSUS", "consensus_score": 1.0},
        "risk_assessment": {"score": 8.8, "severity_band": "CRITICAL"},
        "requires_human_approval": False,
        "human_approval_reasoning": "Autonomous containment applied",
        "root_cause": "Unescaped string concatenation in search controller",
        "technical_timeline": ["T0: Attacker sent UNION SELECT payload"],
        "ranked_actions": [{"action_id": "ACT-01", "priority": "P0_IMMEDIATE", "title": "Block IP"}],
        "reconstruction_findings": {"entry_point": "/api/v1/search via 203.0.113.88", "underlying_condition": "SQLi"},
        "response_plan": {},
        "judge_synthesis": {},
        "debate_revisions": [],
        "grounded_timeline": {},
        "participating_models": {},
    }
    temp_db.save_incident_report(sample_report, org_id="org_security_ops")

    # Query by incident ID
    ctx = retriever.retrieve("Tell me what happened in incident INC-2026-SQLI-99", org_id="org_security_ops")
    assert ctx.is_grounded is True
    assert ctx.incident_data is not None
    assert ctx.incident_data["incident_id"] == "INC-2026-SQLI-99"
    assert ctx.incident_data["incident_category"] == "SQLi"
    assert ctx.incident_data["risk_assessment"]["score"] == 8.8

    # Verify citation source
    sources = [c.source_type for c in ctx.sources_queried]
    assert GroundingSourceType.INCIDENT_RECORD in sources


def test_grounding_aggregate_stats_lookup(temp_db):
    retriever = GroundingRetriever(db=temp_db)

    # Insert 3 sample incident reports
    for idx, (cat, score, sev) in enumerate([("SQLi", 8.8, "CRITICAL"), ("IDOR", 7.5, "HIGH"), ("SQLi", 9.0, "CRITICAL")]):
        temp_db.save_incident_report({
            "report_id": f"REP-STAT-{idx}",
            "incident_id": f"INC-STAT-{idx}",
            "org_id": "org_acme",
            "executive_summary": f"Detected {cat}",
            "incident_category": cat,
            "detection_mesh_confidence": 0.95,
            "consensus_metric": {"status": "FULL_CONSENSUS", "consensus_score": 1.0},
            "risk_assessment": {"score": score, "severity_band": sev},
            "requires_human_approval": False,
            "root_cause": f"Vulnerability in {cat}",
        }, org_id="org_acme")

    # Query aggregate count
    ctx = retriever.retrieve("How many SQLi incidents occurred this week?", org_id="org_acme")
    assert ctx.is_grounded is True
    assert ctx.aggregate_stats is not None
    assert ctx.aggregate_stats["total_incidents"] == 2
    assert ctx.aggregate_stats["category_filter"] == "SQLI"
    assert ctx.aggregate_stats["critical_count"] == 2

    # Verify citation
    sources = [c.source_type for c in ctx.sources_queried]
    assert GroundingSourceType.AGGREGATE_STATISTICS in sources


def test_grounding_mesh_health_lookup(temp_db):
    retriever = GroundingRetriever(db=temp_db)

    ctx = retriever.retrieve("What is the health status of the detection mesh branches?", org_id="org_acme")
    assert ctx.is_grounded is True
    assert ctx.mesh_health is not None
    assert "branches" in ctx.mesh_health
    assert len(ctx.mesh_health["branches"]) >= 6

    sources = [c.source_type for c in ctx.sources_queried]
    assert GroundingSourceType.MESH_HEALTH_TOPOLOGY in sources


def test_grounding_model_performance_lookup(temp_db):
    retriever = GroundingRetriever(db=temp_db)

    ctx = retriever.retrieve("What is the model accuracy and hallucination rate on Phase F benchmarks?", org_id="org_acme")
    assert ctx.is_grounded is True
    assert ctx.benchmark_metrics is not None
    assert ctx.benchmark_metrics["accuracy_rate"] == 100.0
    assert ctx.benchmark_metrics["hallucination_rate"] == 0.0
    assert ctx.benchmark_metrics["total_categories"] == 19

    sources = [c.source_type for c in ctx.sources_queried]
    assert GroundingSourceType.MODEL_BENCHMARK_PERF in sources


def test_grounding_honest_negative_for_missing_data(temp_db):
    retriever = GroundingRetriever(db=temp_db)

    # Completely non-existent incident or question with no matches
    ctx = retriever.retrieve("Tell me about incident INC-NONEXISTENT-99999", org_id="org_acme")
    assert ctx.is_grounded is False
    assert ctx.unretrieved_reason is not None
    assert "No matching incidents" in ctx.unretrieved_reason
    assert "MANDATORY INSTRUCTION" in ctx.to_grounding_prompt_block()


def test_multi_tenant_conversation_memory_isolation(temp_db):
    """
    Task L3 Verification:
    Conversation memory must be strictly partitioned by org_id.
    Org B must never see or retrieve Org A's dialogue history or records.
    """
    # Create conversation for Org Alpha
    conv_alpha = temp_db.create_conversation(user_id="analyst_alpha", org_id="org_alpha", title="Investigating BOLA")
    temp_db.append_message(
        conversation_id=conv_alpha,
        user_id="analyst_alpha",
        org_id="org_alpha",
        role="user",
        content="What was the entry vector for incident INC-ALPHA-101?",
    )
    temp_db.append_message(
        conversation_id=conv_alpha,
        user_id="analyst_alpha",
        org_id="org_alpha",
        role="assistant",
        content="The entry vector was GET /api/v1/user/1042/profile from session 8892.",
        retrieved_context={"incident_id": "INC-ALPHA-101"},
    )

    # 1. Org Alpha retrieves its history
    history_alpha = temp_db.get_conversation_history(conversation_id=conv_alpha, org_id="org_alpha")
    assert len(history_alpha) == 2
    assert history_alpha[0]["content"] == "What was the entry vector for incident INC-ALPHA-101?"

    # 2. Org Beta attempts to access Org Alpha's conversation history -> Must return EMPTY
    history_beta_leak_attempt = temp_db.get_conversation_history(conversation_id=conv_alpha, org_id="org_beta")
    assert len(history_beta_leak_attempt) == 0, "Cross-tenant memory leak detected! Org Beta must not read Org Alpha history."

    # 3. Org Beta lists conversations -> Must NOT see Org Alpha's thread
    conv_list_beta = temp_db.list_user_conversations(user_id="analyst_beta", org_id="org_beta")
    assert not any(c["conversation_id"] == conv_alpha for c in conv_list_beta)
