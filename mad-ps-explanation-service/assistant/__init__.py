"""
MADDY Conversational Assistant Package.
"""

from .agent import MaddyAssistantEngine, maddy_assistant
from .intent import IntentClassifier
from .models import (
    AssistantIntentType,
    AssistantQuery,
    AssistantResponse,
    AssistantStreamEvent,
    DecisionSubmission,
    InlineIncidentCard,
    PendingActionItem,
    ProactiveAlertPayload,
)

__all__ = [
    "MaddyAssistantEngine",
    "maddy_assistant",
    "IntentClassifier",
    "AssistantIntentType",
    "AssistantQuery",
    "AssistantResponse",
    "AssistantStreamEvent",
    "DecisionSubmission",
    "InlineIncidentCard",
    "PendingActionItem",
    "ProactiveAlertPayload",
]
