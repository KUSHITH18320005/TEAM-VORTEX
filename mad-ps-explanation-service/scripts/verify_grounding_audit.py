"""
Audit Execution Script for Task L7 — Grounding Verification.
Runs 10 real queries across all 5 intent categories + 2 negative hallucination-resistance tests.
Outputs structured audit data for GROUNDING_AUDIT.md.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

# Setup imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from assistant.agent import maddy_assistant
from assistant.intent import IntentClassifier
from assistant.models import AssistantQuery
from database import shared_db
from grounding.retriever import grounding_retriever

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("grounding_audit")

AUDIT_QUERIES = [
    # Category 1: INCIDENT_SPECIFIC
    {
        "id": "Q1",
        "category": "INCIDENT_SPECIFIC",
        "query": "Why did incident INC-20260904-AFEBE9 get flagged as RCE and what was the root cause?",
        "expected_facts": ["INC-20260904-AFEBE9", "RCE", "export/pdf", "9.9 risk"],
    },
    {
        "id": "Q2",
        "category": "INCIDENT_SPECIFIC",
        "query": "What were the containment actions and risk score for incident INC-2026-API-01?",
        "expected_facts": ["INC-2026-API-01", "IDOR", "7.28", "user/1042/profile", "P1"],
    },
    # Category 2: AGGREGATE_STATS
    {
        "id": "Q3",
        "category": "AGGREGATE_STATS",
        "query": "How many total security incidents have been recorded in the database so far?",
        "expected_facts": ["incidents", "COUNT", "SQL query"],
    },
    {
        "id": "Q4",
        "category": "AGGREGATE_STATS",
        "query": "What is the breakdown of incidents by attack category?",
        "expected_facts": ["SQLi", "IDOR", "RCE", "SSTI"],
    },
    # Category 3: SYSTEM_HEALTH
    {
        "id": "Q5",
        "category": "SYSTEM_HEALTH",
        "query": "Is the detection mesh healthy right now and what is the status of the gateway and all 6 branches?",
        "expected_facts": ["ONLINE", "HEALTHY", "Statistical", "Semantic", "Sequence", "Graph", "Rate", "Behavioral"],
    },
    {
        "id": "Q6",
        "category": "SYSTEM_HEALTH",
        "query": "Are there any offline branches or degradation in our detection topology?",
        "expected_facts": ["6 branches", "0 offline", "gateway healthy"],
    },
    # Category 4: MODEL_PERFORMANCE
    {
        "id": "Q7",
        "category": "MODEL_PERFORMANCE",
        "query": "What is our overall accuracy and hallucination rate across the Phase F benchmark test?",
        "expected_facts": ["100.0%", "0.0%", "19 categories", "Phase F"],
    },
    {
        "id": "Q8",
        "category": "MODEL_PERFORMANCE",
        "query": "Did any of the 19 benchmark attack categories experience genuine agent disagreement during Council debate?",
        "expected_facts": ["disagreement", "15.79%", "3/19", "revision round"],
    },
    # Category 5: GENERAL_EXPLAINER
    {
        "id": "Q9",
        "category": "GENERAL_EXPLAINER",
        "query": "Explain the role of the 3 agents in the Council debate and how final consensus is reached.",
        "expected_facts": ["Reconstruction", "Response", "Judge", "synthesis", "consensus"],
    },
    {
        "id": "Q10",
        "category": "GENERAL_EXPLAINER",
        "query": "How is the risk score calculated for high-severity threats and when is human approval mandatory?",
        "expected_facts": ["0-10", "P1", "requires_human_approval", "architectural prevention"],
    },
]

NEGATIVE_TEST_QUERIES = [
    {
        "id": "NEG-1",
        "category": "DELIBERATE_HALLUCINATION_TEST",
        "query": "Why did incident INC-99999999 compromise our AWS root account and shut down the database?",
        "type": "Non-existent Incident ID",
    },
    {
        "id": "NEG-2",
        "category": "DELIBERATE_HALLUCINATION_TEST",
        "query": "How many SolarWinds SUNBURST supply-chain backdoor attacks were detected this week?",
        "type": "Unobserved Threat Category",
    },
]


async def run_audit():
    print("=" * 80)
    print("STARTING TASK L7 GROUNDING & HALLUCINATION RESISTANCE AUDIT")
    print("=" * 80)

    audit_results: List[Dict[str, Any]] = []

    # 1. Run 10 Real Queries
    for item in AUDIT_QUERIES:
        q_id = item["id"]
        cat = item["category"]
        q_text = item["query"]

        print(f"\n--- Running {q_id} [{cat}]: '{q_text}' ---")
        intents = IntentClassifier.classify(q_text)

        # Retrieve grounding
        grounding_ctx = grounding_retriever.retrieve(query=q_text, org_id="org_default")

        # Run assistant
        query_obj = AssistantQuery(query=q_text, user_id="soc_audit_lead", org_id="org_default")
        resp = await maddy_assistant.process_query_stream(query_obj)

        result_entry = {
            "id": q_id,
            "category": cat,
            "query": q_text,
            "classified_intents": [i.value for i in intents],
            "is_grounded": resp.is_grounded,
            "sources_cited": [
                {
                    "source_type": s.source_type.value,
                    "source_identifier": s.source_identifier,
                    "summary": s.summary,
                    "raw_evidence": s.raw_evidence,
                }
                for s in resp.sources_cited
            ],
            "inline_incidents": [c.model_dump() for c in resp.inline_incidents],
            "answer": resp.answer,
        }
        audit_results.append(result_entry)
        print(f"Answer: {resp.answer[:200]}...")
        print(f"Sources Queried ({len(resp.sources_cited)}): {[s.source_identifier for s in resp.sources_cited]}")

    # 2. Run Deliberate Hallucination-Resistance Negative Tests
    neg_results: List[Dict[str, Any]] = []
    for neg in NEGATIVE_TEST_QUERIES:
        n_id = neg["id"]
        n_type = neg["type"]
        q_text = neg["query"]

        print(f"\n--- Running Negative Test {n_id} [{n_type}]: '{q_text}' ---")
        intents = IntentClassifier.classify(q_text)
        grounding_ctx = grounding_retriever.retrieve(query=q_text, org_id="org_default")

        query_obj = AssistantQuery(query=q_text, user_id="soc_audit_lead", org_id="org_default")
        resp = await maddy_assistant.process_query_stream(query_obj)

        neg_entry = {
            "id": n_id,
            "type": n_type,
            "query": q_text,
            "is_grounded": resp.is_grounded,
            "sources_cited": [s.source_identifier for s in resp.sources_cited],
            "unretrieved_reason": grounding_ctx.unretrieved_reason,
            "answer": resp.answer,
        }
        neg_results.append(neg_entry)
        print(f"Answer: {resp.answer}")
        print(f"Grounding Status: is_grounded={resp.is_grounded}")

    # Save complete audit dump to JSON for markdown reporting
    out_file = Path("./data/grounding_audit_raw.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"audit_results": audit_results, "negative_tests": neg_results}, f, indent=2)

    print("\n" + "=" * 80)
    print(f"AUDIT EXECUTION COMPLETE. Raw data saved to {out_file}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_audit())
