"""
Intent Classifier for MADDY Conversational Assistant.
Classifies user queries into granular retrieval intents and extracts search entities.
"""

from __future__ import annotations

import re
from typing import List, Tuple
from .models import AssistantIntentType


class IntentClassifier:
    """Classifies user queries to route them to the appropriate Task L2 grounding retrievers."""

    # Keywords for Aggregate Statistics
    AGGREGATE_KEYWORDS = [
        "how many", "count", "total", "statistics", "stats", "today", "this week",
        "this month", "weakest", "highest", "most frequent", "distribution", "breakdown",
        "rate", "average risk", "percentage", "volume", "summary of all"
    ]

    # Keywords for System / Mesh Health
    HEALTH_KEYWORDS = [
        "healthy", "health", "online", "offline", "status", "mesh", "topology",
        "branches", "gateway", "lstm", "services", "operational", "running",
        "is everything up", "system health"
    ]

    # Keywords for Model Performance / Benchmarks
    PERFORMANCE_KEYWORDS = [
        "accuracy", "performance", "benchmark", "hallucination", "precision",
        "phase f", "recall", "f1", "consensus rate", "disagreement", "how accurate",
        "false positive", "ground truth"
    ]

    # Keywords for Incident Specific
    INCIDENT_KEYWORDS = [
        "incident", "attack", "payload", "root cause", "containment", "who attacked",
        "what happened", "flagged as", "why did", "breach", "remediation", "action plan",
        "walk me through", "timeline of", "investigate"
    ]

    # Keywords for Command Execution ("Do work automatically as I say")
    COMMAND_KEYWORDS = [
        "inspect url", "inspect website", "scan url", "scan website", "check url",
        "inspect payload", "test payload", "convene council", "convene the council",
        "start debate", "debate incident", "open dbms", "show dbms", "show database",
        "open explorer", "show topology", "show mesh", "open inspector", "switch to",
        "authorize action", "approve action", "reject action", "block ip", "isolate caller",
        "clear chat", "reset conversation", "export report"
    ]

    # Keywords for Conversational / Greetings / Identity
    GREETING_KEYWORDS = [
        "hi", "hello", "hey", "good morning", "good evening", "who are you", "what can you do",
        "help", "jarvis", "maddy", "introduce yourself", "how are you", "are you ready"
    ]

    @classmethod
    def classify(cls, query: str) -> List[AssistantIntentType]:
        """Classify a query into one or more intents to support multi-intent questions."""
        q_lower = query.lower().strip()
        intents: List[AssistantIntentType] = []

        # 0. Check Command Execution
        if any(k in q_lower for k in cls.COMMAND_KEYWORDS) or q_lower.startswith("inspect ") or q_lower.startswith("convene ") or q_lower.startswith("open "):
            intents.append(AssistantIntentType.COMMAND_EXECUTION)

        # 1. Check for explicit incident IDs (e.g. INC-..., #1042)
        has_incident_id = bool(re.search(r"\b(INC-[\w-]+)\b", query, re.IGNORECASE) or re.search(r"#\w+", query))

        # 2. Check System Health
        if any(k in q_lower for k in cls.HEALTH_KEYWORDS):
            intents.append(AssistantIntentType.SYSTEM_HEALTH)

        # 3. Check Model Performance
        if any(k in q_lower for k in cls.PERFORMANCE_KEYWORDS):
            intents.append(AssistantIntentType.MODEL_PERFORMANCE)

        # 4. Check Aggregate Statistics
        if any(k in q_lower for k in cls.AGGREGATE_KEYWORDS):
            intents.append(AssistantIntentType.AGGREGATE_STATS)

        # 5. Check Incident Specific
        if has_incident_id or any(k in q_lower for k in cls.INCIDENT_KEYWORDS):
            if AssistantIntentType.INCIDENT_SPECIFIC not in intents:
                intents.append(AssistantIntentType.INCIDENT_SPECIFIC)

        # Default fallback
        if not intents:
            intents.append(AssistantIntentType.GENERAL_EXPLAINER)

        return intents

