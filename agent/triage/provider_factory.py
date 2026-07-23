"""Single place that selects and configures a triage provider.

Both the legacy per-incident graph and the batch brief enrichment go through
here, so provider selection, the shared circuit breaker and the configured
model stay identical between them. No caller constructs a provider directly.
"""

from __future__ import annotations

from typing import Optional

from agent.config import get_settings
from agent.triage.circuit_breaker import CircuitBreaker
from agent.triage.provider import TriageProvider


_circuit_breaker: Optional[CircuitBreaker] = None


def get_shared_circuit_breaker() -> CircuitBreaker:
    """The process-wide breaker shared by every provider call."""
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker()
    return _circuit_breaker


def reset_shared_circuit_breaker() -> None:
    """Drop the shared breaker. Used by tests to isolate failure state."""
    global _circuit_breaker
    _circuit_breaker = None


def build_provider(settings: Optional[object] = None) -> TriageProvider:
    """Build the configured provider, or raise if the LLM is disabled."""
    active_settings = settings or get_settings()
    breaker = get_shared_circuit_breaker()

    provider: TriageProvider
    if active_settings.llm_provider == "ollama":  # type: ignore[attr-defined]
        from agent.triage.ollama_provider import OllamaTriageProvider

        provider = OllamaTriageProvider(circuit_breaker=breaker)
    else:
        from agent.triage.groq_provider import GroqTriageProvider

        provider = GroqTriageProvider(circuit_breaker=breaker)
    return provider
