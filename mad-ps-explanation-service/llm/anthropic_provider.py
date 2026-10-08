"""
Anthropic Claude API Provider using direct async HTTPX transport.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from typing import Any, Callable, Optional
import httpx


from .base import BaseLLMProvider

logger = logging.getLogger("mad_ps_explanation.llm.anthropic")


class AnthropicProvider(BaseLLMProvider):
    """LLM Provider for Anthropic Claude models (Claude 3.5 Sonnet, Haiku, Opus)."""

    def __init__(
        self,
        model_name: str = "claude-3-5-sonnet-20241022",
        api_key: Optional[str] = None,
        base_url: str = "https://api.anthropic.com/v1",
    ) -> None:
        raw_key = api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        key = raw_key.strip() if raw_key else None
        super().__init__(model_name=model_name, api_key=key)
        self.base_url = base_url.rstrip("/")


    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> str:
        if not self.api_key:
            raise ValueError("Anthropic API key is not configured. Set ANTHROPIC_API_KEY in environment.")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model_name,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=60.0) as client:
            if stream_callback:
                payload["stream"] = True
                collected_text = []
                async with client.stream(
                    "POST",
                    f"{self.base_url}/messages",
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        err_content = await response.aread()
                        raise RuntimeError(f"Anthropic API error {response.status_code}: {err_content.decode()}")

                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            event_data = json.loads(data_str)
                            if event_data.get("type") == "content_block_delta":
                                delta = event_data.get("delta", {})
                                text_chunk = delta.get("text", "")
                                if text_chunk:
                                    collected_text.append(text_chunk)
                                    if inspect.iscoroutinefunction(stream_callback):
                                        await stream_callback(text_chunk)
                                    else:
                                        stream_callback(text_chunk)

                        except Exception as exc:
                            logger.debug("Error parsing SSE line: %s", exc)

                    full_res = "".join(collected_text)
                    logger.info("[Anthropic] Generated %d chars via stream (Model: %s)", len(full_res), self.model_name)
                    return full_res
            else:
                response = await client.post(
                    f"{self.base_url}/messages",
                    headers=headers,
                    json=payload,
                )
                if response.status_code != 200:
                    raise RuntimeError(f"Anthropic API error {response.status_code}: {response.text}")
                data = response.json()
                content_blocks = data.get("content", [])
                text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
                full_text = "".join(text_parts)
                logger.info("[Anthropic] Generated %d chars (Model: %s)", len(full_text), self.model_name)
                return full_text
