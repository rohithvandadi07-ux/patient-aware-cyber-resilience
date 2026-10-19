import io
import json
import urllib.error
import urllib.request

import pytest
from pydantic import BaseModel

from app.agents.llm_client import MockLLMClient, OllamaLLMClient, generate_validated


class _Out(BaseModel):
    name: str


class _Resp:
    def __init__(self, text: str) -> None:
        self._body = json.dumps({"response": text}).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("http://x", status, "err", {}, io.BytesIO(b"schema rejected"))


def test_sends_the_schema_and_returns_the_response(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(json.loads(req.data))
        return _Resp('{"name": "x"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = OllamaLLMClient(model="m").generate("hi", output_schema=_Out)
    assert out == '{"name": "x"}'
    assert seen[0]["model"] == "m" and seen[0]["stream"] is False
    assert "name" in seen[0]["format"]["properties"]


def test_without_a_schema_uses_plain_json_mode(monkeypatch):
    seen = []
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: (seen.append(json.loads(req.data)), _Resp("{}"))[1]
    )
    OllamaLLMClient().generate("hi")
    assert seen[0]["format"] == "json"


def test_falls_back_to_plain_json_when_the_schema_is_rejected(monkeypatch):
    formats = []

    def fake_urlopen(req, timeout=None):
        formats.append(json.loads(req.data)["format"])
        if len(formats) == 1:
            raise _http_error(400)
        return _Resp('{"name": "ok"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert OllamaLLMClient().generate("hi", output_schema=_Out) == '{"name": "ok"}'
    assert len(formats) == 2 and formats[1] == "json"


def test_missing_model_is_not_retried(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        raise _http_error(404)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="404"):
        OllamaLLMClient().generate("hi", output_schema=_Out)
    assert len(calls) == 1


def test_connection_failure_is_a_clear_runtime_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="Ollama call failed"):
        OllamaLLMClient().generate("hi")


def test_generate_validated_hands_the_schema_to_schema_aware_clients():
    received = []

    class _Aware:
        supports_schema = True

        def generate(self, prompt, output_schema=None):
            received.append(output_schema)
            return '{"name": "a"}'

    assert generate_validated(_Aware(), "p", _Out, "agent").name == "a"
    assert received == [_Out]


def test_mock_client_path_is_unchanged():
    client = MockLLMClient(responses=['{"name": "a"}'])
    assert generate_validated(client, "p", _Out, "agent").name == "a"
