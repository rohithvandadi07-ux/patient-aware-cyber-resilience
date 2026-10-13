import pytest
from pydantic import BaseModel

from app.agents.llm_client import AgentFailure, MockLLMClient, generate_validated


class _DummyOutput(BaseModel):
    value: int
    label: str


def test_generate_validated_succeeds_on_first_try():
    client = MockLLMClient(responses=[_DummyOutput(value=1, label="ok").model_dump_json()])
    result = generate_validated(client, "prompt", _DummyOutput, agent_name="test_agent")
    assert result == _DummyOutput(value=1, label="ok")
    assert len(client.calls) == 1


def test_generate_validated_retries_once_on_schema_violation_then_succeeds():
    client = MockLLMClient(
        responses=[
            '{"value": "not an int", "label": "bad"}',  # fails schema validation
            _DummyOutput(value=2, label="fixed").model_dump_json(),
        ]
    )
    result = generate_validated(client, "prompt", _DummyOutput, agent_name="test_agent")
    assert result == _DummyOutput(value=2, label="fixed")
    assert len(client.calls) == 2
    # The retry prompt must carry the validation error forward, per the
    # architecture spec's "retried once with the validation error appended."
    assert "previous response failed schema validation" in client.calls[1]


def test_generate_validated_retries_once_on_malformed_json_then_succeeds():
    client = MockLLMClient(
        responses=["not even json", _DummyOutput(value=3, label="fixed").model_dump_json()]
    )
    result = generate_validated(client, "prompt", _DummyOutput, agent_name="test_agent")
    assert result == _DummyOutput(value=3, label="fixed")
    assert len(client.calls) == 2


def test_generate_validated_raises_agent_failure_after_second_failure():
    client = MockLLMClient(responses=["not json", "still not json"])
    with pytest.raises(AgentFailure) as exc_info:
        generate_validated(client, "prompt", _DummyOutput, agent_name="investigation")
    assert exc_info.value.agent_name == "investigation"
    assert len(client.calls) == 2


def test_generate_validated_never_returns_unvalidated_data_after_exhausting_retry():
    # Even though the second response is syntactically valid JSON, it still
    # violates the schema -- must still raise, never pass it through.
    client = MockLLMClient(responses=["not json", '{"value": "nope", "label": "nope"}'])
    with pytest.raises(AgentFailure):
        generate_validated(client, "prompt", _DummyOutput, agent_name="investigation")


def test_mock_llm_client_raises_when_responses_exhausted():
    client = MockLLMClient(responses=[])
    with pytest.raises(RuntimeError, match="no scripted responses"):
        client.generate("prompt")


# --- GeminiLLMClient (post-Phase-15) ---
# No real network call anywhere below -- `google.genai.Client` is patched
# out so these tests run offline and deterministically, same as every
# other test in this file. What they prove: GeminiLLMClient.generate's own
# wiring (model/contents/config passed through correctly, response.text
# returned as-is, real failures wrapped as RuntimeError rather than
# swallowed) -- not that live Gemini reasoning occurred. That can only be
# proven with a real GEMINI_API_KEY, which this test suite deliberately
# does not require to pass.

from unittest.mock import MagicMock, patch  # noqa: E402

from app.agents.llm_client import GeminiLLMClient  # noqa: E402


def test_gemini_llm_client_returns_response_text():
    fake_response = MagicMock(text='{"value": 1, "label": "ok"}')
    fake_client = MagicMock()
    fake_client.models.generate_content.return_value = fake_response

    with patch("google.genai.Client", return_value=fake_client) as mock_ctor:
        gemini = GeminiLLMClient(api_key="test-key-not-real", model="gemini-2.0-flash")
        result = gemini.generate("some prompt")

    mock_ctor.assert_called_once_with(api_key="test-key-not-real")
    assert result == '{"value": 1, "label": "ok"}'
    assert gemini.calls == ["some prompt"]
    call_kwargs = fake_client.models.generate_content.call_args.kwargs
    assert call_kwargs["model"] == "gemini-2.0-flash"
    assert call_kwargs["contents"] == "some prompt"


def test_gemini_llm_client_wraps_api_failure_as_runtime_error():
    fake_client = MagicMock()
    fake_client.models.generate_content.side_effect = Exception("connection reset")

    with patch("google.genai.Client", return_value=fake_client):
        gemini = GeminiLLMClient(api_key="test-key-not-real")
        with pytest.raises(RuntimeError, match="Gemini API call failed"):
            gemini.generate("some prompt")


def test_gemini_llm_client_raises_on_empty_response_text():
    fake_response = MagicMock(text=None)
    fake_client = MagicMock()
    fake_client.models.generate_content.return_value = fake_response

    with patch("google.genai.Client", return_value=fake_client):
        gemini = GeminiLLMClient(api_key="test-key-not-real")
        with pytest.raises(RuntimeError, match="no text content"):
            gemini.generate("some prompt")


def test_gemini_llm_client_plugs_into_generate_validated_like_any_other_client():
    """End to end through the same retry/validation path every agent
    uses -- proves GeminiLLMClient is a drop-in LLMClient, not a special
    case `generate_validated` needs to know about."""
    fake_response = MagicMock(text=_DummyOutput(value=7, label="from-gemini").model_dump_json())
    fake_client = MagicMock()
    fake_client.models.generate_content.return_value = fake_response

    with patch("google.genai.Client", return_value=fake_client):
        gemini = GeminiLLMClient(api_key="test-key-not-real")
        result = generate_validated(gemini, "prompt", _DummyOutput, agent_name="test_agent")

    assert result == _DummyOutput(value=7, label="from-gemini")
