"""LLMClient abstraction + schema-validated retry-once logic.

Architecture spec Section 11: "an `LLMClient` interface
(`generate_structured(prompt, output_schema) -> T`) that each agent calls
through -- concretely, every agent's LLM call is immediately validated against
its Pydantic output schema; a response that fails validation is retried once
with the validation error appended, then surfaces as an agent failure rather
than being passed downstream unvalidated." And: "What's deliberately not
decided yet: [...] which concrete LLM backend to call first [...] made after
the schemas above are implemented and testable against mocked LLM responses."

This module therefore defines the interface and the retry policy, plus a
`MockLLMClient` for tests -- no real LLM backend (Anthropic/OpenAI/etc. SDK
call) is wired in yet. That stays an open Phase 4+ decision per the
architecture doc's own words; building it now would be choosing a backend
under feature pressure rather than after the schemas are proven.
"""

import json
from dataclasses import dataclass, field
from typing import Protocol, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class AgentFailure(Exception):
    """Raised when an agent's LLM call cannot produce a schema-valid output
    even after one retry. Architecture spec: "an agent that can't produce a
    valid structured output after retry marks the incident
    `investigation_stalled` (or the equivalent per stage) [...] The closed
    loop does not silently proceed on bad agent output." Agents catch this,
    record a failed trace, and surface the stall -- they never swallow it and
    guess.
    """

    def __init__(self, agent_name: str, last_error: str) -> None:
        self.agent_name = agent_name
        self.last_error = last_error
        super().__init__(
            f"{agent_name}: failed to produce a valid structured output after retry: {last_error}"
        )


class LLMClient(Protocol):
    """What every agent calls through. `generate_structured` takes a prompt
    string and the Pydantic model class the response must validate against,
    and returns a raw string -- validation and retry live in
    `generate_validated` below, one level up, so every concrete `LLMClient`
    implementation (mock now, a real backend later) only has to implement the
    single raw call, not reimplement the retry policy.
    """

    def generate(self, prompt: str) -> str: ...


@dataclass
class MockLLMClient:
    """Test double: returns pre-scripted responses in order, one per call.
    Lets agent unit tests exercise the full "generate -> validate -> retry
    once -> AgentFailure" path deterministically, without any real LLM call --
    this is exactly the "mocked LLM responses" Section 19's Phase 4 gate
    requires.
    """

    responses: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list, repr=False)

    def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        if not self.responses:
            raise RuntimeError("MockLLMClient has no scripted responses left for this call")
        return self.responses.pop(0)


def generate_validated(client: LLMClient, prompt: str, output_schema: type[T], agent_name: str) -> T:
    """Call `client.generate`, validate the result against `output_schema`,
    and retry once with the validation error appended to the prompt if it
    fails. Raises `AgentFailure` if the retry also fails to validate.

    This is the one place the retry policy is implemented -- every agent
    calls this instead of hand-rolling its own try/except around
    `client.generate`, so the policy (and its test coverage) lives in exactly
    one place.
    """
    raw_response = client.generate(prompt)
    try:
        return _parse(raw_response, output_schema)
    except (ValidationError, json.JSONDecodeError) as first_error:
        retry_prompt = (
            f"{prompt}\n\nYour previous response failed schema validation with this error:\n"
            f"{first_error}\n\nRespond again with a corrected JSON object matching the schema."
        )
        retry_response = client.generate(retry_prompt)
        try:
            return _parse(retry_response, output_schema)
        except (ValidationError, json.JSONDecodeError) as second_error:
            raise AgentFailure(agent_name, str(second_error)) from second_error


def _parse(raw_response: str, output_schema: type[T]) -> T:
    payload = json.loads(raw_response)
    return output_schema.model_validate(payload)
