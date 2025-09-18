"""Provider factory, cost model and budget enforcement."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from ..core.config import Settings, get_settings
from .base import Provider, ProviderConfiguration, ProviderError
from .simulation import SimulationProvider

logger = logging.getLogger(__name__)

#: Published list price per **one million** tokens (USD).  These are public
#: prices and are used for *estimates only*; the dashboard always labels the
#: value as an estimate.
PRICE_PER_MILLION: dict[str, tuple[float, float]] = {
    # model prefix -> (input, output)
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "o3-mini": (1.10, 4.40),
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-7-sonnet": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-haiku-4": (1.00, 5.00),
    "mistral-large": (2.00, 6.00),
    "llama-3.3-70b": (0.12, 0.30),
    "qwen2.5": (0.00, 0.00),
    "gemma": (0.00, 0.00),
}

#: Fallback price used when a model is unknown.
DEFAULT_PRICE = (1.00, 3.00)


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate the cost of a provider call in USD."""
    name = (model or "").lower()
    price = DEFAULT_PRICE
    for prefix, candidate in sorted(PRICE_PER_MILLION.items(), key=lambda item: -len(item[0])):
        if prefix in name:
            price = candidate
            break
    else:
        if name.startswith(("ollama/", "qwen", "gemma", "llama3.2", "local")):
            price = (0.0, 0.0)
    input_cost = (prompt_tokens / 1_000_000) * price[0]
    output_cost = (completion_tokens / 1_000_000) * price[1]
    return round(input_cost + output_cost, 8)


def build_provider(
    config: ProviderConfiguration,
    settings: Settings | None = None,
) -> Provider:
    """Instantiate the provider described by ``config``."""
    settings = settings or get_settings()
    provider_type = (config.provider_type or "").lower()

    if provider_type in {"simulation", "offline", "mock"}:
        simulation_config = ProviderConfiguration(
            provider_type="simulation",
            base_url="",
            api_key="",
            model=config.model or "simulation://deterministic-planner",
            timeout_seconds=config.timeout_seconds,
            max_retries=0,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            options=config.options,
        )
        return SimulationProvider(simulation_config)

    if provider_type in {"anthropic", "claude", "anthropic-compatible"}:
        from .anthropic import AnthropicProvider

        return AnthropicProvider(config)

    if provider_type in {"openai", "openrouter", "ollama", "custom", "openai-compatible"}:
        from .openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(config)

    raise ProviderError(
        f"Unknown provider type '{config.provider_type}'.",
        "provider_unknown_type",
        status=400,
    )


def provider_types() -> list[dict[str, Any]]:
    """Describe the supported provider types for the settings screen."""
    return [
        {
            "id": "ollama",
            "label": "Ollama (local, free)",
            "format": "openai-compatible",
            "default_base_url": "http://localhost:11434/v1",
            "requires_key": False,
            "notes": "Runs a local model. No API key and no cost.",
        },
        {
            "id": "openai",
            "label": "OpenAI API",
            "format": "openai-compatible",
            "default_base_url": "https://api.openai.com/v1",
            "requires_key": True,
            "notes": "A ChatGPT Plus subscription does not include API credits.",
        },
        {
            "id": "anthropic",
            "label": "Anthropic Claude API",
            "format": "anthropic",
            "default_base_url": "https://api.anthropic.com",
            "requires_key": True,
            "notes": "A Claude subscription does not include API credits.",
        },
        {
            "id": "openrouter",
            "label": "OpenRouter",
            "format": "openai-compatible",
            "default_base_url": "https://openrouter.ai/api/v1",
            "requires_key": True,
            "notes": "Aggregator for many models; prices vary per model.",
        },
        {
            "id": "custom",
            "label": "Custom endpoint",
            "format": "openai-compatible",
            "default_base_url": "",
            "requires_key": False,
            "notes": "Any OpenAI-compatible base URL, with an optional API key.",
        },
        {
            "id": "simulation",
            "label": "Offline simulation",
            "format": "builtin",
            "default_base_url": "",
            "requires_key": False,
            "notes": "Deterministic offline planner. No network, no cost.",
        },
    ]


class BudgetGuard:
    """Enforce per-session and per-day spending limits."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def check(
        self, *, session_cost: float, daily_cost: float, estimated_next: float = 0.0
    ) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for a new provider call."""
        if not self.settings.budget_enabled:
            return True, "Budget enforcement is disabled."
        if session_cost >= self.settings.budget_session_usd:
            return False, (
                f"The session budget of ${self.settings.budget_session_usd:.2f} has been "
                f"reached (${session_cost:.4f} spent)."
            )
        if daily_cost >= self.settings.budget_daily_usd:
            return False, (
                f"The daily budget of ${self.settings.budget_daily_usd:.2f} has been "
                f"reached (${daily_cost:.4f} spent today)."
            )
        if estimated_next and (session_cost + estimated_next) > self.settings.budget_session_usd:
            return False, (
                "The next provider call would exceed the session budget of "
                f"${self.settings.budget_session_usd:.2f}."
            )
        return True, "Within budget."


def config_from_profile(profile: Mapping[str, Any]) -> ProviderConfiguration:
    """Build a :class:`ProviderConfiguration` from a stored profile row."""
    return ProviderConfiguration(
        provider_type=str(profile.get("provider_type") or "custom"),
        base_url=str(profile.get("base_url") or ""),
        api_key=str(profile.get("api_key") or ""),
        model=str(profile.get("model") or ""),
        timeout_seconds=int(profile.get("timeout_seconds") or 120),
        max_retries=int(profile.get("max_retries") or 2),
        max_tokens=int(profile.get("max_tokens") or 4096),
        temperature=float(profile.get("temperature") or 0.2),
        extra_headers=dict(profile.get("extra_headers") or {}),
        options=dict(profile.get("options") or {}),
    )
