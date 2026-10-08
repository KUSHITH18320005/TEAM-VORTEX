"""
LLM Configuration and Runtime Provider Manager for MAD-PS Explanation Layer & Browser Council v2.
Enables dynamic switching between Real LLM Providers (Google Gemini, OpenAI,
Groq, Anthropic Claude, Ollama Local, OpenRouter, DeepSeek, and Custom Endpoints)
with persistent storage, live credential testing, and runtime hot-reloading for the 7-Model Panel.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import dotenv
    dotenv.load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
    dotenv.load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

from schemas.report import PanelistConfig

from .anthropic_provider import AnthropicProvider
from .base import BaseLLMProvider
from .gemini_provider import GeminiProvider
from .mock_provider import MockLLMProvider
from .openai_provider import OpenAIProvider

logger = logging.getLogger("mad_ps_explanation.llm.config_manager")

DATA_DIR = Path(os.environ.get("MAD_PS_DATA_DIR", "./data"))
CONFIG_FILE = DATA_DIR / "llm_config.json"

PROVIDER_DEFAULTS = {
    "gemini": {
        "model_name": "gemini-3.5-flash-lite",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "env_keys": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "display_name": "Google Gemini",
    },
    "openai": {
        "model_name": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1",
        "env_keys": ["OPENAI_API_KEY"],
        "display_name": "OpenAI",
    },
    "groq": {
        "model_name": "llama-3.3-70b-versatile",
        "base_url": "https://api.groq.com/openai/v1",
        "env_keys": ["GROQ_API_KEY"],
        "display_name": "Groq (Ultra-Fast)",
    },
    "anthropic": {
        "model_name": "claude-3-5-sonnet-20241022",
        "base_url": "https://api.anthropic.com/v1",
        "env_keys": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        "display_name": "Anthropic Claude",
    },
    "ollama": {
        "model_name": "llama3:latest",
        "base_url": "http://localhost:11434/v1",
        "env_keys": [],
        "display_name": "Ollama (Local / Free)",
    },
    "openrouter": {
        "model_name": "deepseek/deepseek-chat",
        "base_url": "https://openrouter.ai/api/v1",
        "env_keys": ["OPENROUTER_API_KEY"],
        "display_name": "OpenRouter",
    },
    "deepseek": {
        "model_name": "deepseek-chat",
        "base_url": "https://api.deepseek.com/v1",
        "env_keys": ["DEEPSEEK_API_KEY"],
        "display_name": "DeepSeek",
    },
    "custom": {
        "model_name": "default",
        "base_url": "http://localhost:8000/v1",
        "env_keys": [],
        "display_name": "Custom OpenAI-Compatible",
    },
}

DEFAULT_PANELISTS: List[Dict[str, Any]] = [
    {
        "id": "panelist_1",
        "name": "Dr. Elena Vance",
        "title": "Senior Forensic Engineer",
        "role_specialty": "Forensics & Reconstruction Specialist",
        "role_type": "RECONSTRUCTION",
        "provider": "anthropic",
        "model_name": "claude-3-5-sonnet-20241022",
        "base_url": "https://api.anthropic.com/v1",
        "api_key": "",
        "temperature": 0.1,
        "max_tokens": 2048,
        "weight": 1.2,
        "enabled": True,
        "avatar_color": "#00f2fe",
        "badge_label": "FORENSICS",
    },
    {
        "id": "panelist_2",
        "name": "Marcus Thorne",
        "title": "Principal Threat Researcher",
        "role_specialty": "Threat Attribution & Intelligence Lead",
        "role_type": "RECONSTRUCTION",
        "provider": "openai",
        "model_name": "gpt-4o",
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "weight": 1.15,
        "enabled": True,
        "avatar_color": "#10a37f",
        "badge_label": "THREAT INTEL",
    },
    {
        "id": "panelist_3",
        "name": "Sarah Lin",
        "title": "Application Security Architect",
        "role_specialty": "Exploit Payload & AST Code Auditor",
        "role_type": "RECONSTRUCTION",
        "provider": "gemini",
        "model_name": "gemini-3.6-flash",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "api_key": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "weight": 1.1,
        "enabled": True,
        "avatar_color": "#4285f4",
        "badge_label": "EXPLOIT ANALYSIS",
    },
    {
        "id": "panelist_4",
        "name": "Viktor Novak",
        "title": "Incident Response Commander",
        "role_specialty": "High-Velocity Containment Tactician",
        "role_type": "RESPONSE",
        "provider": "groq",
        "model_name": "llama-3.3-70b-versatile",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "weight": 1.05,
        "enabled": True,
        "avatar_color": "#f55036",
        "badge_label": "FAST MITIGATION",
    },
    {
        "id": "panelist_5",
        "name": "Maya Patel",
        "title": "Infrastructure Security Lead",
        "role_specialty": "Architectural Resilience & System Hardening",
        "role_type": "RESPONSE",
        "provider": "groq",
        "model_name": "mixtral-8x7b-32768",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "weight": 1.0,
        "enabled": True,
        "avatar_color": "#a855f7",
        "badge_label": "RESILIENCE",
    },
    {
        "id": "panelist_6",
        "name": "David Chen",
        "title": "Chief Compliance Officer",
        "role_specialty": "Regulatory Compliance & Blast-Radius Auditor",
        "role_type": "RESPONSE",
        "provider": "deepseek",
        "model_name": "deepseek-chat",
        "base_url": "https://api.deepseek.com/v1",
        "api_key": "",
        "temperature": 0.2,
        "max_tokens": 2048,
        "weight": 1.0,
        "enabled": True,
        "avatar_color": "#06b6d4",
        "badge_label": "COMPLIANCE",
    },
]

DEFAULT_JUDGE: Dict[str, Any] = {
    "id": "judge_magistrate",
    "name": "The Arbiter",
    "title": "Chief Magistrate & Synthesis Judge",
    "role_specialty": "Judicial Synthesis, Factuality Audit & Action Prioritization",
    "role_type": "JUDGE",
    "provider": "gemini",
    "model_name": "gemini-3.1-pro-preview",
    "base_url": "https://generativelanguage.googleapis.com/v1beta",
    "api_key": "",
    "temperature": 0.1,
    "max_tokens": 2048,
    "avatar_color": "#ffd700",
    "badge_label": "CHIEF MAGISTRATE",
}


class LLMConfigManager:
    """Manages real LLM configuration, persistence, and dynamic provider instances for Council v2."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_path = config_path or CONFIG_FILE
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._active_assistant_provider: Optional[BaseLLMProvider] = None
        self._config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from disk, falling back to environment variables and defaults."""
        data: Dict[str, Any] = {}
        def _is_valid_key(val: Optional[str]) -> bool:
            if not val:
                return False
            val = val.strip().strip("'\"<>")
            if len(val) < 15:
                return False
            if any(p in val.lower() for p in ["test-key", "placeholder", "demo", "dummy", "fake", "none"]):
                return False
            return True

        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        saved_key = data.get("api_key")
                        provider = data.get("provider", "gemini")
                        if _is_valid_key(saved_key) and provider in PROVIDER_DEFAULTS:
                            for k in PROVIDER_DEFAULTS[provider]["env_keys"]:
                                if not os.environ.get(k):
                                    os.environ[k] = saved_key
            except Exception as exc:
                logger.warning("Could not read LLM config from %s: %s", self.config_path, exc)

        # Merge or initialize top-level assistant provider with environment variables
        current_env_gemini = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if _is_valid_key(current_env_gemini):
            data["provider"] = "gemini"
            data["model_name"] = "gemini-3.6-flash"
            data["api_key"] = current_env_gemini.strip().strip("'\"<>")
            data["base_url"] = PROVIDER_DEFAULTS["gemini"]["base_url"]
            data["temperature"] = 0.2
            data["max_tokens"] = 2048
        elif not _is_valid_key(data.get("api_key")):
            for prov, meta in PROVIDER_DEFAULTS.items():
                for env_key in meta["env_keys"]:
                    val = os.environ.get(env_key)
                    if _is_valid_key(val):
                        data["provider"] = prov
                        data["model_name"] = meta["model_name"]
                        data["api_key"] = val.strip().strip("'\"<>")
                        data["base_url"] = meta["base_url"]
                        data["temperature"] = 0.2
                        data["max_tokens"] = 2048
                        break
                if _is_valid_key(data.get("api_key")):
                    break

        if not data.get("provider"):
            data["provider"] = "gemini"
            data["model_name"] = "gemini-3.6-flash"
            data["api_key"] = ""
            data["base_url"] = PROVIDER_DEFAULTS["gemini"]["base_url"]
            data["temperature"] = 0.2
            data["max_tokens"] = 2048

        # Ensure panelists list is populated
        if not data.get("panelists") or not isinstance(data["panelists"], list) or len(data["panelists"]) < 6:
            data["panelists"] = DEFAULT_PANELISTS

        # Ensure judge config is populated
        if not data.get("judge") or not isinstance(data["judge"], dict):
            data["judge"] = DEFAULT_JUDGE

        # Auto-fill missing keys in panelists from environment
        for p in data["panelists"]:
            prov = p.get("provider", "openai")
            if not p.get("api_key") and prov in PROVIDER_DEFAULTS:
                for k in PROVIDER_DEFAULTS[prov]["env_keys"]:
                    env_v = os.environ.get(k)
                    if env_v:
                        p["api_key"] = env_v.strip()
                        break

        # Auto-fill judge key
        judge_prov = data["judge"].get("provider", "gemini")
        if not data["judge"].get("api_key") and judge_prov in PROVIDER_DEFAULTS:
            for k in PROVIDER_DEFAULTS[judge_prov]["env_keys"]:
                env_v = os.environ.get(k)
                if env_v:
                    data["judge"]["api_key"] = env_v.strip()
                    break

        return data

    def get_config_summary(self) -> Dict[str, Any]:
        """Return public configuration with masked credentials and panel summary."""
        prov = self._config.get("provider", "gemini")
        api_key = self._config.get("api_key", "")
        model_name = self._config.get("model_name", "")
        base_url = self._config.get("base_url", "")

        is_configured = bool(api_key.strip()) or prov == "ollama"

        masked_key = ""
        if api_key:
            masked_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "***"

        return {
            "provider": prov,
            "model_name": model_name,
            "base_url": base_url,
            "is_configured": is_configured,
            "masked_key": masked_key,
            "is_real_llm": is_configured,
            "available_providers": [
                {
                    "id": k,
                    "name": v["display_name"],
                    "default_model": v["model_name"],
                    "default_url": v["base_url"],
                    "requires_key": k != "ollama",
                }
                for k, v in PROVIDER_DEFAULTS.items()
            ],
            "panel_summary": self.get_panel_summary(),
        }

    def get_panel_summary(self) -> Dict[str, Any]:
        """Return structured summary of the 7-Model Panel and Chief Magistrate."""
        panelists_raw = self._config.get("panelists", DEFAULT_PANELISTS)
        judge_raw = self._config.get("judge", DEFAULT_JUDGE)

        sanitized_panelists = []
        for p in panelists_raw:
            key_val = p.get("api_key", "")
            has_key = bool(key_val and len(key_val.strip()) > 5) or p.get("provider") == "ollama"
            sanitized_panelists.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "title": p.get("title"),
                "role_specialty": p.get("role_specialty"),
                "provider": p.get("provider"),
                "model_name": p.get("model_name"),
                "base_url": p.get("base_url"),
                "weight": p.get("weight", 1.0),
                "enabled": p.get("enabled", True),
                "avatar_color": p.get("avatar_color", "#00f2fe"),
                "badge_label": p.get("badge_label", "PANELIST"),
                "is_live_key": has_key,
                "masked_key": (f"{key_val[:3]}...{key_val[-3:]}" if len(key_val) > 6 else ("ACTIVE" if has_key else "SIMULATED")),
            })

        judge_key = judge_raw.get("api_key", "")
        judge_has_key = bool(judge_key and len(judge_key.strip()) > 5) or judge_raw.get("provider") == "ollama"
        sanitized_judge = {
            "id": judge_raw.get("id", "judge_magistrate"),
            "name": judge_raw.get("name", "The Arbiter"),
            "title": judge_raw.get("title", "Chief Magistrate & Synthesis Judge"),
            "role_specialty": judge_raw.get("role_specialty", "Judicial Synthesis & Action Prioritization"),
            "provider": judge_raw.get("provider", "gemini"),
            "model_name": judge_raw.get("model_name", "gemini-2.0-flash"),
            "avatar_color": judge_raw.get("avatar_color", "#ffd700"),
            "badge_label": judge_raw.get("badge_label", "CHIEF MAGISTRATE"),
            "is_live_key": judge_has_key,
            "masked_key": (f"{judge_key[:3]}...{judge_key[-3:]}" if len(judge_key) > 6 else ("ACTIVE" if judge_has_key else "SIMULATED")),
        }

        return {
            "total_panelists": len(sanitized_panelists),
            "panelists": sanitized_panelists,
            "judge": sanitized_judge,
        }

    def get_council_panelist_configs(self) -> List[PanelistConfig]:
        """Return verified PanelistConfig Pydantic models for all 7 panelists."""
        raw_list = self._config.get("panelists", DEFAULT_PANELISTS)
        res: List[PanelistConfig] = []
        for item in raw_list:
            res.append(PanelistConfig(**item))
        return res

    def get_panelist_provider(self, panelist: PanelistConfig) -> BaseLLMProvider:
        """Create or return an LLM provider for a specific panelist."""
        prov = panelist.provider.lower()
        key = panelist.api_key or ""
        if not key and prov in PROVIDER_DEFAULTS:
            for k in PROVIDER_DEFAULTS[prov]["env_keys"]:
                env_v = os.environ.get(k)
                if env_v:
                    key = env_v.strip()
                    break

        if (key and "placeholder" not in key.lower()) or prov == "ollama":
            try:
                return self.create_provider_instance(
                    provider=prov,
                    api_key=key,
                    model_name=panelist.model_name,
                    base_url=panelist.base_url or PROVIDER_DEFAULTS.get(prov, {}).get("base_url", ""),
                )
            except Exception as exc:
                logger.warning("Could not instantiate live provider for %s (%s): %s", panelist.name, prov, exc)

        # High-fidelity simulated provider with panelist specialty persona
        return MockLLMProvider(
            model_name=panelist.model_name,
            provider_label=f"{panelist.provider}:{panelist.id}",
        )

    def get_judge_provider(self) -> BaseLLMProvider:
        """Create or return provider for Chief Magistrate Judge."""
        j = self._config.get("judge", DEFAULT_JUDGE)
        prov = j.get("provider", "gemini").lower()
        key = j.get("api_key", "")
        if not key and prov in PROVIDER_DEFAULTS:
            for k in PROVIDER_DEFAULTS[prov]["env_keys"]:
                env_v = os.environ.get(k)
                if env_v:
                    key = env_v.strip()
                    break

        if (key and "placeholder" not in key.lower()) or prov == "ollama":
            try:
                return self.create_provider_instance(
                    provider=prov,
                    api_key=key,
                    model_name=j.get("model_name", "gemini-2.0-flash"),
                    base_url=j.get("base_url", PROVIDER_DEFAULTS.get(prov, {}).get("base_url", "")),
                )
            except Exception as exc:
                logger.warning("Could not instantiate live Judge provider: %s", exc)

        return MockLLMProvider(
            model_name=j.get("model_name", "gemini-2.0-flash"),
            provider_label=f"{prov}:judge_magistrate",
        )

    def save_panelist_config(self, panelist_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a specific panelist in the 7-model panel and persist to disk."""
        panelists = self._config.get("panelists", DEFAULT_PANELISTS)
        updated = False
        for p in panelists:
            if p["id"] == panelist_id:
                for k, v in updates.items():
                    if v is not None:
                        p[k] = v
                updated = True
                break

        if not updated and panelist_id == "judge_magistrate":
            judge_cfg = self._config.get("judge", DEFAULT_JUDGE)
            for k, v in updates.items():
                if v is not None:
                    judge_cfg[k] = v
            self._config["judge"] = judge_cfg
            updated = True

        if updated:
            self._save_to_disk()
            logger.info("Saved updated configuration for panelist %s", panelist_id)

        return self.get_panel_summary()

    def _save_to_disk(self) -> None:
        """Save active configuration to JSON config file."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2)
        except Exception as exc:
            logger.error("Failed to persist LLM config to disk: %s", exc)

    def save_config(
        self,
        provider: str,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        """Update and persist primary LLM configuration."""
        if provider not in PROVIDER_DEFAULTS:
            raise ValueError(f"Unknown provider: {provider}")

        meta = PROVIDER_DEFAULTS[provider]
        final_model = model_name or meta["model_name"]
        final_url = base_url or meta["base_url"]

        if api_key is None or api_key == "":
            final_key = self._config.get("api_key", "") if self._config.get("provider") == provider else ""
        else:
            final_key = api_key.strip()

        self._config["provider"] = provider
        self._config["model_name"] = final_model
        self._config["api_key"] = final_key
        self._config["base_url"] = final_url
        self._config["temperature"] = temperature
        self._config["max_tokens"] = max_tokens
        self._config["updated_at"] = time.time()

        if final_key:
            for env_k in meta["env_keys"]:
                os.environ[env_k] = final_key

        self._save_to_disk()
        self._active_assistant_provider = None
        logger.info("Updated Real LLM config: provider=%s, model=%s", provider, final_model)

        return self.get_config_summary()

    def create_provider_instance(
        self,
        provider: str,
        api_key: str,
        model_name: str,
        base_url: str,
    ) -> BaseLLMProvider:
        """Instantiate a specific real provider."""
        provider = provider.lower()

        if provider == "gemini":
            return GeminiProvider(
                model_name=model_name or "gemini-3.5-flash-lite",
                api_key=api_key or None,
                base_url=base_url or "https://generativelanguage.googleapis.com/v1beta",
            )
        elif provider == "anthropic":
            return AnthropicProvider(
                model_name=model_name or "claude-3-5-sonnet-20241022",
                api_key=api_key or None,
            )
        elif provider in ("openai", "groq", "openrouter", "ollama", "deepseek", "custom"):
            eff_key = api_key if (api_key or provider != "ollama") else "ollama-no-key-required"
            return OpenAIProvider(
                model_name=model_name,
                api_key=eff_key,
                base_url=base_url,
                provider_label=provider,
            )
        else:
            return MockLLMProvider(model_name="mock-fallback", provider_label="mock")

    def get_assistant_provider(self) -> BaseLLMProvider:
        """Return active LLM provider for MADDY Assistant, checking config and environment keys."""
        if self._active_assistant_provider is not None:
            return self._active_assistant_provider

        prov = self._config.get("provider", "gemini").lower()
        api_key = self._config.get("api_key", "").strip()
        model_name = self._config.get("model_name", "")
        base_url = self._config.get("base_url", "")

        # Check environment keys for configured provider if not explicitly in config
        if not api_key and prov in PROVIDER_DEFAULTS:
            for k in PROVIDER_DEFAULTS[prov]["env_keys"]:
                env_v = os.environ.get(k)
                if env_v and len(env_v.strip()) > 10:
                    api_key = env_v.strip()
                    break

        # Fallback check across other real providers in environment
        if not api_key:
            for check_prov in ["gemini", "openai", "anthropic", "groq", "deepseek"]:
                for k in PROVIDER_DEFAULTS.get(check_prov, {}).get("env_keys", []):
                    env_v = os.environ.get(k)
                    if env_v and len(env_v.strip()) > 10:
                        prov = check_prov
                        api_key = env_v.strip()
                        model_name = PROVIDER_DEFAULTS[check_prov]["model_name"]
                        base_url = PROVIDER_DEFAULTS[check_prov]["base_url"]
                        break
                if api_key:
                    break

        if api_key or prov == "ollama":
            try:
                instance = self.create_provider_instance(
                    provider=prov,
                    api_key=api_key,
                    model_name=model_name,
                    base_url=base_url,
                )
                self._active_assistant_provider = instance
                logger.info("Active MADDY Assistant using Real LLM: %s (%s)", prov, model_name)
                return instance
            except Exception as exc:
                logger.error("Failed to initialize real LLM provider %s: %s", prov, exc)

        # Honest unconfigured fallback that informs the operator rather than fabricating answers
        class UnconfiguredMaddyProvider(BaseLLMProvider):
            def __init__(self):
                super().__init__(model_name="maddy-unconfigured", api_key=None)
            @property
            def provider_name(self) -> str:
                return "unconfigured"
            async def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2, max_tokens: int = 2048, stream_callback: Optional[Any] = None) -> str:
                if "[GROUNDING STATUS: NO MATCHING DATA FOUND IN DATABASE OR TELEMETRY]" in prompt or "does not exist" in prompt:
                    msg = "No matching records or telemetry found in the database. The requested incident or metric does not exist in the platform archive."
                elif "[VERIFIED FACTUAL GROUNDING DATA" in prompt:
                    msg = "Retrieved verified factual platform telemetry from database records. Note: Configure a real LLM API key (Gemini, OpenAI, Anthropic, or Groq) in .env or via Settings for advanced narrative synthesis."
                else:
                    msg = "MADDY Real AI Engine is currently unconfigured. Please configure a valid API key (Gemini, OpenAI, Anthropic, or Groq) in .env or via the AI Settings modal to enable real LLM reasoning."
                if stream_callback:
                    if inspect.iscoroutinefunction(stream_callback):
                        await stream_callback(msg)
                    else:
                        stream_callback(msg)
                return msg

        import inspect
        return UnconfiguredMaddyProvider()

    def get_council_providers(self) -> Tuple[BaseLLMProvider, BaseLLMProvider, BaseLLMProvider]:
        """Legacy 3-provider getter for backward compatibility."""
        p_configs = self.get_council_panelist_configs()
        p1 = self.get_panelist_provider(p_configs[0])
        p2 = self.get_panelist_provider(p_configs[3])
        p3 = self.get_judge_provider()
        return p1, p2, p3

    async def test_connection(
        self,
        provider: str,
        api_key: str,
        model_name: str,
        base_url: str,
    ) -> Dict[str, Any]:
        """Send a real diagnostic test ping to verify credentials and connectivity."""
        start_t = time.perf_counter()
        try:
            instance = self.create_provider_instance(
                provider=provider,
                api_key=api_key,
                model_name=model_name,
                base_url=base_url,
            )
            test_prompt = "Hello! Please reply in exactly one short sentence confirming that the AI connection is active."
            response_text = await instance.generate(
                prompt=test_prompt,
                temperature=0.2,
                max_tokens=64,
            )
            latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
            return {
                "success": True,
                "provider": provider,
                "model": model_name,
                "latency_ms": latency_ms,
                "reply": response_text.strip(),
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_t) * 1000, 1)
            return {
                "success": False,
                "provider": provider,
                "model": model_name,
                "latency_ms": latency_ms,
                "error": str(exc),
            }


# Global singleton instance
llm_config_manager = LLMConfigManager()
