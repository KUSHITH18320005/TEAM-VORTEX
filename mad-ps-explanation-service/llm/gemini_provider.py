"""
Google Gemini API Provider for MAD-PS Ecosystem.
Uses async HTTPX transport for live SSE streaming token-by-token,
candidate model fallbacks, and explicit error surfacing per Phase AA Task AA1.
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

logger = logging.getLogger("mad_ps_explanation.llm.gemini")

# Candidate models in priority order (verified active and high-quota on key)
GEMINI_CANDIDATE_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3-flash-preview",
    "gemini-3.6-flash",
]


class GeminiProvider(BaseLLMProvider):
    """LLM Provider for Google Gemini models with native async token-by-token SSE streaming."""

    def __init__(
        self,
        model_name: str = "gemini-3.5-flash-lite",
        api_key: Optional[str] = None,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
    ) -> None:
        raw_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        clean_key = raw_key.strip().strip("'\"<>")
        super().__init__(model_name=model_name, api_key=clean_key or None)
        self.base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        stream_callback: Optional[Callable[[str], Any]] = None,
    ) -> str:
        if not self.api_key:
            raise ValueError(
                "Google Gemini API key is not configured. Set GEMINI_API_KEY in .env or via Settings."
            )

        candidates = []
        for m in [self.model_name] + GEMINI_CANDIDATE_MODELS:
            clean_m = m.replace("models/", "")
            if clean_m not in candidates:
                candidates.append(clean_m)

        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        if system_prompt:
            payload["system_instruction"] = {
                "parts": [{"text": system_prompt}]
            }

        last_error = None
        async with httpx.AsyncClient(timeout=45.0) as client:
            for model_candidate in candidates:
                for attempt in range(2):
                    try:
                        stream_url = f"{self.base_url}/models/{model_candidate}:streamGenerateContent?alt=sse&key={self.api_key}"
                        collected = []
                        async with client.stream("POST", stream_url, json=payload) as response:
                            if response.status_code != 200:
                                err_content = await response.aread()
                                err_text = err_content.decode("utf-8", errors="replace")
                                if response.status_code in (400, 403) and ("key" in err_text.lower() or "invalid" in err_text.lower() or "api_key" in err_text.lower()):
                                    raise ValueError(f"Gemini API key invalid: {err_text}")
                                if response.status_code == 429:
                                    if attempt == 0:
                                        await asyncio.sleep(1.5)
                                        continue
                                    last_error = RuntimeError(f"Gemini API HTTP 429 Rate Limit: {err_text}")
                                    break
                                if response.status_code in (404, 500, 503):
                                    last_error = RuntimeError(f"Gemini API HTTP {response.status_code}: {err_text}")
                                    break
                                raise RuntimeError(f"Gemini API HTTP {response.status_code}: {err_text}")

                            async for line in response.aiter_lines():
                                if not line or not line.startswith("data: "):
                                    continue
                                data_str = line[6:].strip()
                                try:
                                    chunk_data = json.loads(data_str)
                                    cands = chunk_data.get("candidates", [])
                                    if cands:
                                        parts = cands[0].get("content", {}).get("parts", [])
                                        token = "".join(p.get("text", "") for p in parts)
                                        if token:
                                            collected.append(token)
                                            if stream_callback:
                                                if inspect.iscoroutinefunction(stream_callback):
                                                    await stream_callback(token)
                                                else:
                                                    stream_callback(token)
                                except Exception:
                                    pass

                        full_res = "".join(collected)
                        if full_res.strip():
                            self.model_name = model_candidate
                            logger.info("[Gemini-SSE] Generated %d chars via %s", len(full_res), model_candidate)
                            return full_res

                    except ValueError as exc:
                        raise exc
                    except Exception as exc:
                        last_error = exc
                        break

        if last_error:
            raise last_error
        raise RuntimeError("Failed to generate response across all Gemini model candidates.")
