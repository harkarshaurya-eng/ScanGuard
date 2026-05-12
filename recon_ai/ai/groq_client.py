"""Groq API client with streaming, retries, and JSON mode support."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx

from recon_ai.config import AppSettings


class GroqClient:
    """Async client for Groq's OpenAI-compatible chat completions API."""

    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.groq_base_url.rstrip("/"),
            timeout=settings.http_timeout_seconds,
            headers={"Authorization": f"Bearer {settings.groq_api_key}"} if settings.groq_api_key else {},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def complete_chat(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> str:
        """Return a full completion response."""
        payload = self._build_payload(messages, stream=False, json_mode=json_mode, temperature=temperature, max_tokens=max_tokens)
        data = await self._request(payload)
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("Groq response did not contain a chat completion message.") from exc

    async def astream_chat(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> AsyncIterator[str]:
        """Yield streamed content tokens."""
        payload = self._build_payload(messages, stream=True, json_mode=json_mode, temperature=temperature, max_tokens=max_tokens)
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with self._client.stream("POST", "/chat/completions", json=payload) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data = line[6:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            payload_line = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        choices = payload_line.get("choices", [])
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})
                        content = delta.get("content")
                        if content:
                            yield str(content)
                return
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                last_error = exc
                await asyncio.sleep(2**attempt)
        raise RuntimeError(f"Groq streaming request failed: {last_error}") from last_error

    async def plan_structured(self, messages: list[dict[str, str]]) -> dict[str, object]:
        """Request a structured JSON planning response."""
        content = await self.complete_chat(messages, json_mode=True, temperature=0.0, max_tokens=900)
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Groq JSON mode response was not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Groq JSON mode response did not produce an object.")
        return payload

    def _build_payload(
        self,
        messages: list[dict[str, str]],
        *,
        stream: bool,
        json_mode: bool,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self.settings.groq_model,
            "messages": messages,
            "stream": stream,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    async def _request(self, payload: dict[str, object]) -> dict[str, object]:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = await self._client.post("/chat/completions", json=payload)
                if response.status_code >= 500:
                    response.raise_for_status()
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise RuntimeError("Groq returned a non-object response.")
                return data
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                last_error = exc
                await asyncio.sleep(2**attempt)
        raise RuntimeError(f"Groq request failed after retries: {last_error}") from last_error

