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
