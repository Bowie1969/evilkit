"""OpenAI-compatible chat completion clients for the operator and auditor.

Uses only the standard library so the brain proof-of-concept does not introduce
new dependencies. A dry-run mode returns deterministic canned responses so the
controller loop can be tested without API keys or network access.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ModelError",
    "ChatMessage",
    "ChatRequest",
    "ChatCompletionClient",
]


class ModelError(Exception):
    """Raised when a model request fails or returns an unexpected shape."""


@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatRequest:
    messages: list[ChatMessage]
    model: str = ""
    temperature: float = 0.2
    max_tokens: int | None = None
    response_format: dict[str, str] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [m.to_dict() for m in self.messages],
            "temperature": self.temperature,
        }
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        if self.response_format is not None:
            payload["response_format"] = self.response_format
        payload.update(self.extra)
        return payload


def _default_dry_run_response(messages: list[ChatMessage]) -> str:
    """Return a safe placeholder completion when no model is configured."""
    if not messages:
        return '{"verdict": "CONTINUE", "reason": "no messages provided"}'
    system = " ".join(m.content for m in messages if m.role == "system")
    user = " ".join(m.content for m in messages if m.role == "user")
    if "operator" in system.lower() or "action" in user.lower():
        return (
            '{"goal": "dry-run reconnaissance", '
            '"command": "ping -c 1 127.0.0.1", '
            '"expected_result": "one reply from loopback"}'
        )
    return (
        '{"verdict": "CONTINUE", '
        '"reason": "dry-run auditor: no API configured", '
        '"confidence": "low", '
        '"required_test": ""}'
    )


class ChatCompletionClient:
    """Minimal OpenAI-compatible chat client."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        *,
        dry_run: bool = False,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.dry_run = dry_run
        self.timeout = timeout

    @classmethod
    def from_brain_config(
        cls,
        config,
        *,
        role: str,
        dry_run: bool = False,
    ) -> "ChatCompletionClient":
        """Build a client from a ``BrainConfig`` for the given role.

        ``role`` must be ``"operator"`` or ``"auditor"``.
        """
        if role == "operator":
            return cls(
                base_url=config.resolved_operator_url(),
                model=config.resolved_operator_model(),
                api_key=config.resolved_operator_key() or None,
                dry_run=dry_run,
            )
        if role == "auditor":
            return cls(
                base_url=config.resolved_auditor_url(),
                model=config.resolved_auditor_model(),
                api_key=config.resolved_auditor_key() or None,
                dry_run=dry_run,
            )
        raise ValueError(f"unknown role: {role!r}")

    def _endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def complete(self, request: ChatRequest) -> str:
        """Send a chat request and return the first completion's content."""
        if self.dry_run or not self.base_url:
            return _default_dry_run_response(request.messages)

        payload = request.to_dict()
        payload["model"] = self.model or payload.get("model", "")
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self._endpoint(),
            data=data,
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                detail = json.loads(body)
                message = detail.get("error", {}).get("message", str(exc))
            except json.JSONDecodeError:
                message = body.decode("utf-8", errors="replace") or str(exc)
            raise ModelError(f"model request failed: {message}") from exc
        except urllib.error.URLError as exc:
            raise ModelError(f"model request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ModelError("model request timed out") from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ModelError(f"model returned invalid JSON: {exc}") from exc

        choices = parsed.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ModelError("model response has no choices")

        message = choices[0].get("message", {})
        content = message.get("content")
        if not isinstance(content, str):
            raise ModelError("model completion has no text content")
        return content
