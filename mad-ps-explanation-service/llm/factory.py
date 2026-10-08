"""
Factory for instantiating multi-provider LLM clients across Council agents.
Ensures distinct model providers are assigned across Agent 1, Agent 2, and Agent 3.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional, Tuple

from .anthropic_provider import AnthropicProvider
from .base import BaseLLMProvider
from .gemini_provider import GeminiProvider
from .mock_provider import MockLLMProvider
from .openai_provider import OpenAIProvider

logger = logging.getLogger("mad_ps_explanation.llm.factory")


class LLMFactory:
    """Creates and assigns distinct LLM providers across the 3 Council roles."""

    @classmethod
    def create_council_providers(
        cls,
        force_mock: bool = False,
    ) -> Tuple[BaseLLMProvider, BaseLLMProvider, BaseLLMProvider]:
        """
        Return (reconstruction_provider, response_provider, judge_provider).
        Guarantees at least 2 distinct model providers across the roles.
        """
        if force_mock:
            return cls._create_mock_providers()

        def _is_valid_key(val: Optional[str]) -> bool:
            if not val:
                return False
            val = val.strip()
            if len(val) < 20:
                return False
            if "\\" in val or "/" in val or " " in val:
                return False
            if any(p in val.lower() for p in ["placeholder", "demo", "master_key", "test_key", "dummy", "fake"]):
                return False
            return True

        claude_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

        has_claude = _is_valid_key(claude_key)
        has_openai = _is_valid_key(openai_key)
        has_gemini = _is_valid_key(gemini_key)


        available_keys_count = sum([has_claude, has_openai, has_gemini])

        # Scenario 1: Both Claude & OpenAI available
        if has_claude and has_openai:
            p1 = AnthropicProvider(model_name=os.environ.get("RECONSTRUCTION_MODEL", "claude-3-5-sonnet-20241022"))
            p2 = OpenAIProvider(model_name=os.environ.get("RESPONSE_MODEL", "gpt-4o-mini"))
            # Strongest model for Judge
            p3 = AnthropicProvider(model_name=os.environ.get("JUDGE_MODEL", "claude-3-5-sonnet-20241022"))
            logger.info("Configured council with Anthropic (Agent 1), OpenAI (Agent 2), and Anthropic (Judge).")
            return p1, p2, p3

        # Scenario 2: Claude & Gemini available
        if has_claude and has_gemini:
            p1 = AnthropicProvider(model_name="claude-3-5-sonnet-20241022")
            p2 = GeminiProvider(model_name="gemini-1.5-flash")
            p3 = GeminiProvider(model_name="gemini-1.5-pro")
            logger.info("Configured council with Anthropic (Agent 1), Gemini (Agent 2), and Gemini Pro (Judge).")
            return p1, p2, p3

        # Scenario 3: OpenAI & Gemini available
        if has_openai and has_gemini:
            p1 = OpenAIProvider(model_name="gpt-4o-mini")
            p2 = GeminiProvider(model_name="gemini-1.5-flash")
            p3 = OpenAIProvider(model_name="gpt-4o")
            logger.info("Configured council with OpenAI (Agent 1), Gemini (Agent 2), and OpenAI GPT-4o (Judge).")
            return p1, p2, p3

        # Scenario 4: Single provider available -> pair with a complementary mock/simulated provider to ensure multi-model debate
        if has_claude:
            p1 = AnthropicProvider(model_name="claude-3-5-sonnet-20241022")
            p2 = MockLLMProvider(model_name="gpt-4o-simulated", provider_label="openai-simulated")
            p3 = AnthropicProvider(model_name="claude-3-5-sonnet-20241022")
            logger.info("Configured council with Claude (Agent 1 & Judge) and OpenAI Simulated (Agent 2).")
            return p1, p2, p3

        if has_openai:
            p1 = OpenAIProvider(model_name="gpt-4o-mini")
            p2 = MockLLMProvider(model_name="claude-3-5-sonnet-simulated", provider_label="anthropic-simulated")
            p3 = OpenAIProvider(model_name="gpt-4o")
            logger.info("Configured council with OpenAI (Agent 1 & Judge) and Anthropic Simulated (Agent 2).")
            return p1, p2, p3

        if has_gemini:
            p1 = GeminiProvider(model_name="gemini-1.5-flash")
            p2 = MockLLMProvider(model_name="claude-3-5-sonnet-simulated", provider_label="anthropic-simulated")
            p3 = GeminiProvider(model_name="gemini-1.5-pro")
            logger.info("Configured council with Gemini (Agent 1 & Judge) and Anthropic Simulated (Agent 2).")
            return p1, p2, p3

        # Fallback: Multi-model simulated council
        return cls._create_mock_providers()

    @classmethod
    def create_assistant_provider(cls, force_mock: bool = False) -> BaseLLMProvider:
        """Create the best available LLM provider for the MADDY conversational assistant."""
        if force_mock:
            return MockLLMProvider(model_name="maddy-copilot-simulated", provider_label="maddy-mock")

        def _is_valid_key(val: Optional[str]) -> bool:
            if not val:
                return False
            val = val.strip()
            return len(val) >= 15 and "\\" not in val and "/" not in val and " " not in val

        claude_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

        if _is_valid_key(claude_key):
            return AnthropicProvider(model_name=os.environ.get("ASSISTANT_MODEL", "claude-3-5-sonnet-20241022"))
        if _is_valid_key(openai_key):
            return OpenAIProvider(model_name=os.environ.get("ASSISTANT_MODEL", "gpt-4o"))
        if _is_valid_key(gemini_key):
            return GeminiProvider(model_name=os.environ.get("ASSISTANT_MODEL", "gemini-1.5-pro"))

        return MockLLMProvider(model_name="maddy-copilot-simulated", provider_label="maddy-mock")

    @classmethod
    def _create_mock_providers(cls) -> Tuple[BaseLLMProvider, BaseLLMProvider, BaseLLMProvider]:
        p1 = MockLLMProvider(model_name="claude-3-5-sonnet", provider_label="anthropic-mock")
        p2 = MockLLMProvider(model_name="gpt-4o", provider_label="openai-mock")
        p3 = MockLLMProvider(model_name="gemini-1.5-pro", provider_label="gemini-mock")
        logger.info("Configured simulated multi-provider council (Anthropic, OpenAI, Gemini).")
        return p1, p2, p3

