"""
Base interface for LLM Providers in the MAD-PS Explanation Service.
"""

from __future__ import annotations

import abc
from typing import Any, Callable, Optional


class BaseLLMProvider(abc.ABC):
    """Abstract base class for all LLM providers supporting streaming and non-streaming generation."""

    def __init__(self, model_name: str, api_key: Optional[str] = None) -> None:
        self.model_name = model_name
        self.api_key = api_key

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Return provider identifier (e.g. 'anthropic', 'openai', 'gemini', 'mock')."""
        pass

    @property
    def display_name(self) -> str:
        """User-friendly display name of the provider and model."""
        return f"{self.provider_name}:{self.model_name}"

    @abc.abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> str:
        """
        Generate completion text from the model.
        If stream_callback is provided, text chunks should be passed to it as they arrive.
        """
        pass
