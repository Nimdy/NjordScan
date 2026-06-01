"""AI explanation providers.

Three tiers, all opt-in. The OFFLINE tier (the knowledge base shipped with every
finding) is not here — it always works without this module. This file adds:

  - OllamaProvider — a local model (private, free). Default for --explain-with-ai.
  - ClaudeProvider — Anthropic API (needs ANTHROPIC_API_KEY).
  - OpenAIProvider — OpenAI API (needs OPENAI_API_KEY).

``httpx`` is only needed for these and lives in the ``[ai]`` extra; it is imported
lazily so the package installs and runs fine without it.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional, Tuple


class ProviderError(RuntimeError):
    """Raised when a provider cannot run (missing key, unreachable, etc.)."""


def _load_httpx():
    try:
        import httpx  # noqa: PLC0415 — lazy by design
    except ImportError as exc:  # pragma: no cover
        raise ProviderError(
            "AI explanations need the optional 'ai' extra. Install it with:\n"
            "    pip install 'njordscan[ai]'"
        ) from exc
    return httpx


class Provider(ABC):
    name: str = ""
    is_local: bool = False

    @abstractmethod
    def check(self) -> Tuple[bool, str]:
        """Return (available, human_reason). Cheap; no model call."""

    @abstractmethod
    def complete(self, system: str, user: str, *, timeout: float = 60.0) -> str:
        """Return the model's text for the given prompt, or raise ProviderError."""


class OllamaProvider(Provider):
    """Local model via Ollama (https://ollama.com). Private and free."""

    name = "ollama"
    is_local = True

    def __init__(self, model: Optional[str] = None, host: Optional[str] = None) -> None:
        self.model = model or os.getenv("NJORDSCAN_AI_MODEL", "qwen2.5-coder:7b")
        self.host = (host or os.getenv("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")

    def check(self) -> Tuple[bool, str]:
        try:
            httpx = _load_httpx()
        except ProviderError as exc:
            return False, str(exc)
        try:
            resp = httpx.get(f"{self.host}/api/tags", timeout=3.0)
            resp.raise_for_status()
        except Exception:  # noqa: BLE001
            return False, (
                f"Ollama not reachable at {self.host}. Install it from https://ollama.com, "
                f"then run:  ollama pull {self.model}"
            )
        return True, f"ollama ({self.model}) at {self.host}"

    def complete(self, system: str, user: str, *, timeout: float = 60.0) -> str:
        httpx = _load_httpx()
        try:
            resp = httpx.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "system": system,
                    "prompt": user,
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            return str(resp.json().get("response", "")).strip()
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"Ollama request failed: {exc}") from exc


class _HTTPKeyProvider(Provider):
    """Shared base for remote API providers that authenticate with an env key."""

    env_key: str = ""
    endpoint: str = ""

    def __init__(self, model: str) -> None:
        self.model = os.getenv("NJORDSCAN_AI_MODEL", model)

    def _api_key(self) -> str:
        key = os.getenv(self.env_key)
        if not key:
            raise ProviderError(f"{self.name} needs the {self.env_key} environment variable to be set.")
        return key

    def check(self) -> Tuple[bool, str]:
        try:
            _load_httpx()
            self._api_key()
        except ProviderError as exc:
            return False, str(exc)
        return True, f"{self.name} ({self.model})"


class ClaudeProvider(_HTTPKeyProvider):
    name = "claude"
    env_key = "ANTHROPIC_API_KEY"
    endpoint = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: Optional[str] = None) -> None:
        super().__init__(model or "claude-haiku-4-5-20251001")

    def complete(self, system: str, user: str, *, timeout: float = 60.0) -> str:
        httpx = _load_httpx()
        try:
            resp = httpx.post(
                self.endpoint,
                headers={
                    "x-api-key": self._api_key(),
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 600,
                    "temperature": 0.2,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"Claude request failed: {exc}") from exc


class OpenAIProvider(_HTTPKeyProvider):
    name = "openai"
    env_key = "OPENAI_API_KEY"
    endpoint = "https://api.openai.com/v1/chat/completions"

    def __init__(self, model: Optional[str] = None) -> None:
        super().__init__(model or "gpt-4o-mini")

    def complete(self, system: str, user: str, *, timeout: float = 60.0) -> str:
        httpx = _load_httpx()
        try:
            resp = httpx.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self._api_key()}", "content-type": "application/json"},
                json={
                    "model": self.model,
                    "temperature": 0.2,
                    "max_tokens": 600,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            choices = resp.json().get("choices", [])
            return choices[0]["message"]["content"].strip() if choices else ""
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"OpenAI request failed: {exc}") from exc


_PROVIDERS = {
    "ollama": OllamaProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
}


def get_provider(name: str) -> Provider:
    factory = _PROVIDERS.get(name)
    if factory is None:
        raise ProviderError(f"Unknown AI provider: {name!r}. Choose from: {', '.join(_PROVIDERS)}")
    return factory()


def is_remote(name: str) -> bool:
    factory = _PROVIDERS.get(name)
    return bool(factory) and not getattr(factory, "is_local", False)
