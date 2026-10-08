"""Tests for evilkit.models — the OpenAI-compatible chat client."""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.config import BrainConfig  # noqa: E402
from evilkit.models import (  # noqa: E402
    ChatCompletionClient,
    ChatMessage,
    ChatRequest,
    ModelError,
)


class TestChatRequest(EvilkitTestCase):
    def test_payload_includes_required_fields(self):
        req = ChatRequest(
            messages=[ChatMessage(role="system", content="behave")],
            model="m",
            temperature=0.5,
            max_tokens=100,
        )
        payload = req.to_dict()
        self.assertEqual(payload["model"], "m")
        self.assertEqual(payload["temperature"], 0.5)
        self.assertEqual(payload["max_tokens"], 100)
        self.assertEqual(payload["messages"], [{"role": "system", "content": "behave"}])

    def test_response_format_is_optional(self):
        req = ChatRequest(messages=[], response_format={"type": "json_object"})
        self.assertEqual(req.to_dict()["response_format"], {"type": "json_object"})


class TestClientConstruction(EvilkitTestCase):
    def test_from_brain_config_builds_operator_client(self):
        brain = BrainConfig(
            operator_url="http://glm",
            operator_model="glm-4",
            operator_key="op-secret",
        )
        client = ChatCompletionClient.from_brain_config(brain, role="operator")
        self.assertEqual(client.base_url, "http://glm")
        self.assertEqual(client.model, "glm-4")
        self.assertEqual(client.api_key, "op-secret")

    def test_from_brain_config_builds_auditor_client(self):
        brain = BrainConfig(
            auditor_url="http://deepseek",
            auditor_model="deepseek-chat",
            auditor_key="audit-secret",
        )
        client = ChatCompletionClient.from_brain_config(brain, role="auditor")
        self.assertEqual(client.base_url, "http://deepseek")
        self.assertEqual(client.model, "deepseek-chat")
        self.assertEqual(client.api_key, "audit-secret")

    def test_from_brain_config_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            ChatCompletionClient.from_brain_config(BrainConfig(), role="critic")

    def test_empty_api_key_becomes_none(self):
        brain = BrainConfig(operator_key="")
        client = ChatCompletionClient.from_brain_config(brain, role="operator")
        self.assertIsNone(client.api_key)


class TestDryRunResponses(EvilkitTestCase):
    def test_operator_dry_run_returns_a_json_action(self):
        client = ChatCompletionClient("http://x", "m", dry_run=True)
        req = ChatRequest(messages=[ChatMessage(role="user", content="operator: next action")])
        content = client.complete(req)
        parsed = json.loads(content)
        self.assertIn("command", parsed)
        self.assertIn("goal", parsed)

    def test_auditor_dry_run_returns_a_verdict(self):
        client = ChatCompletionClient("http://x", "m", dry_run=True)
        req = ChatRequest(messages=[ChatMessage(role="user", content="auditor: review")])
        content = client.complete(req)
        parsed = json.loads(content)
        self.assertEqual(parsed["verdict"], "CONTINUE")

    def test_missing_url_uses_dry_run(self):
        client = ChatCompletionClient("", "m", dry_run=False)
        content = client.complete(ChatRequest(messages=[]))
        self.assertIn("verdict", content)


class TestMockedNetwork(EvilkitTestCase):
    def _mock_response(self, content: str, status: int = 200):
        body = json.dumps({
            "choices": [{"message": {"role": "assistant", "content": content}}]
        }).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return body

        return FakeResponse(), status

    def test_successful_completion_returns_content(self):
        client = ChatCompletionClient("http://api", "m", api_key="k")
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = self._mock_response("hello")[0]
            result = client.complete(ChatRequest(messages=[ChatMessage(role="user", content="hi")]))
        self.assertEqual(result, "hello")
        self.assertEqual(urlopen.call_count, 1)

    def test_http_error_includes_server_message(self):
        client = ChatCompletionClient("http://api", "m", api_key="k")

        class FakeError(urllib.error.HTTPError):
            def __init__(self):
                super().__init__("http://api", 401, "Unauthorized", {}, None)

            def read(self):
                return json.dumps({"error": {"message": "bad key"}}).encode("utf-8")

        with mock.patch("urllib.request.urlopen", side_effect=FakeError()):
            with self.assertRaises(ModelError) as ctx:
                client.complete(ChatRequest(messages=[]))
        self.assertIn("bad key", str(ctx.exception))

    def test_invalid_json_raises_model_error(self):
        client = ChatCompletionClient("http://api", "m")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"not json"

        with mock.patch("urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(ModelError):
                client.complete(ChatRequest(messages=[]))

    def test_missing_choices_raises_model_error(self):
        client = ChatCompletionClient("http://api", "m")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps({"choices": []}).encode("utf-8")

        with mock.patch("urllib.request.urlopen", return_value=FakeResponse()):
            with self.assertRaises(ModelError):
                client.complete(ChatRequest(messages=[]))


if __name__ == "__main__":
    unittest.main()
