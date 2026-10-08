"""
OpenAI API Provider using direct async HTTPX transport.
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

logger = logging.getLogger("mad_ps_explanation.llm.openai")



class OpenAIProvider(BaseLLMProvider):
    """LLM Provider for OpenAI models (GPT-4o, GPT-4o-mini, o1)."""

    def __init__(
        self,
        model_name: str = "gpt-4o",
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        provider_label: Optional[str] = None,
    ) -> None:
        key = api_key or os.environ.get("OPENAI_API_KEY")
        super().__init__(model_name=model_name, api_key=key)
        self.base_url = base_url.rstrip("/")
        self._provider_label = provider_label

    @property
    def provider_name(self) -> str:
        if self._provider_label:
            return self._provider_label
        if "groq" in self.base_url:
            return "groq"
        if "openrouter" in self.base_url:
            return "openrouter"
        if "11434" in self.base_url:
            return "ollama"
        if "deepseek" in self.base_url:
            return "deepseek"
        return "openai"

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> str:
        if not self.api_key:
            raise ValueError("OpenAI API key is not configured. Set OPENAI_API_KEY in environment.")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            if stream_callback:
                payload["stream"] = True
                collected_text = []
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        err_content = await response.aread()
                        raise RuntimeError(f"OpenAI API error {response.status_code}: {err_content.decode()}")

                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            event_data = json.loads(data_str)
                            choices = event_data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    collected_text.append(content)
                                    if inspect.iscoroutinefunction(stream_callback):
                                        await stream_callback(content)
                                    else:
                                        stream_callback(content)

                        except Exception as exc:
                            logger.debug("Error parsing SSE line: %s", exc)

                    full_res = "".join(collected_text)
                    logger.info("[OpenAI/%s] Generated %d chars via stream", self.provider_name, len(full_res))
                    return full_res
            else:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                if response.status_code != 200:
                    raise RuntimeError(f"OpenAI/{self.provider_name} API error {response.status_code}: {response.text}")
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    res_text = choices[0].get("message", {}).get("content", "")
                    logger.info("[OpenAI/%s] Generated %d chars (Model: %s)", self.provider_name, len(res_text), self.model_name)
                    return res_text
                return ""
