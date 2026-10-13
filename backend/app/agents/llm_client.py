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
`MockLLMClient` for tests -- every agent's schema/retry logic was proven
against it first, deliberately, before any real backend was wired in.

**Post-Phase-15 update:** that real backend now exists -- `GeminiLLMClient`
below, wired to Google's Gemini API via the `google-genai` SDK, selected
with `Settings.llm_backend="gemini"` (default stays `"mock"`, so nothing
about the default dev/test experience changes). See `GeminiLLMClient`'s own
docstring for why Gemini, why now, and exactly what it does and does not
handle.
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


@dataclass
class GeminiLLMClient:
    """Real `LLMClient` backed by Google's Gemini API (`google-genai` SDK).

    Post-Phase-15, user-directed: this project went a long time without a
    real LLM backend -- not from inability, but because this module's own
    history records the deliberate choice to prove the agent schemas/retry
    policy against `MockLLMClient` first, "after the schemas above are
    implemented and testable against mocked LLM responses" (see this
    module's top docstring). They are now proven (every one of the five
    agents' unit tests, plus `tests/test_lifecycle_integration.py`'s real
    end-to-end chain, all pass against `MockLLMClient`), so wiring a real
    backend is no longer "choosing a backend under feature pressure" -- it
    is the next planned step.

    Selected via `Settings.llm_backend == "gemini"` (default stays
    `"mock"` -- see `app/core/app_factory.py::_register_state`); never the
    default, so every pre-existing test and the default dev experience are
    unaffected unless a `GEMINI_API_KEY` is actually configured.

    `generate` asks for `response_mime_type="application/json"` so Gemini
    is constrained to emit a JSON object directly -- `generate_validated`
    (above) still does the real schema validation and retry-once policy on
    whatever comes back; this class does not pre-validate or special-case
    Gemini's output in any way, so a malformed response is handled by the
    exact same path a malformed `MockLLMClient` response would be.

    Raises `RuntimeError` at call time (not at construction) if the
    `google-genai` package is not importable, or if the API call itself
    fails (network error, invalid key, rate limit, etc.) -- these surface to
    the caller as an ordinary exception, the same as any other
    `LLMClient.generate` failure; nothing here retries at the transport
    level or swallows a real failure to produce a fabricated response.
    """

    api_key: str
    model: str = "gemini-2.0-flash"
    calls: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError(
                "GeminiLLMClient requires the 'google-genai' package (see requirements.txt); "
                "it is not importable in this environment."
            ) from exc
        self._client = genai.Client(api_key=self.api_key)

    def generate(self, prompt: str) -> str:
        from google.genai import types

        self.calls.append(prompt)
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json"),
            )
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: any transport/API
            # failure (auth, network, rate limit, quota) is a real failure this method
            # must not hide behind a fabricated response. It propagates as-is; the caller
            # (an agent's run() via run_agent_call) handles it the same as any other
            # unexpected exception from `client.generate`.
            raise RuntimeError(f"Gemini API call failed: {exc}") from exc

        if response.text is None:
            raise RuntimeError(
                "Gemini API returned no text content (e.g. blocked by a safety filter) -- "
                "nothing to validate against the output schema."
            )
        return response.text
