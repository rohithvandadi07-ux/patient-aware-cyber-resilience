"""The agent execution loop.

Genuine multi-step agency: an agent gathers evidence through controlled
tools across several turns, then produces a validated structured output.
Not a single prompt-and-answer.

The loop owns the properties the specification requires of agents - state,
tools, structured schemas, validation, retry, failure handling and
authority boundaries - so that a specialist agent is a small declaration
rather than a reimplementation of orchestration.

FAILURE SEMANTICS
-----------------
* A tool error is an observation, not a crash: the agent sees the error and
  may try something else. This is what lets an agent recover from a missing
  data source.
* An **authority violation** aborts the run immediately with status
  ``ABORTED_AUTHORITY``. It is a structural fault, not a condition to
  retry around, and it is recorded so the evaluation can report
  attempted-violation counts.
* Invalid structured output is retried up to ``max_retries`` with the
  validation error fed back. Persistent failure yields
  ``VALIDATION_FAILED`` and the output is **discarded**, never passed
  downstream - a malformed agent output must not reach the risk engine.
* Exceeding ``max_tool_calls`` or the wall-clock budget ends the run as
  ``TIMED_OUT`` with whatever was gathered, so a looping agent cannot stall
  an incident indefinitely.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from agents.core.provider import LLMProvider, ProviderTurn
from agents.core.schemas import schema_for
from agents.tools.registry import (
    AuthorityViolation,
    ToolContext,
    ToolRegistry,
)
from backend.app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    AssertionClass,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    AgentFinding,
    AgentRunRecord,
    IncidentContextPackage,
    ToolCallRecord,
)


@dataclass
class AgentConfig:
    """Execution limits. Defaults are deliberately modest."""

    #: Tool-call budget. Sized for the planned sequence plus headroom for
    #: an agent that explores. The response-planning agent originally
    #: exceeded a budget of 16 by evaluating candidates one per call; the
    #: fix was a batched comparison tool, not merely a larger budget.
    max_tool_calls: int = 24
    max_retries: int = 2
    timeout_seconds: float = 120.0
    max_turns: int = 32


@dataclass
class AgentSpec:
    """Declaration of one specialist agent."""

    role: AgentRole
    system_prompt: str
    task_template: str
    #: Fixed tool allowlist. Cannot be extended at run time.
    allowlist: frozenset[str]

    def task_prompt(self, package: IncidentContextPackage) -> str:
        incident = package.incident
        return self.task_template.format(
            incident_id=incident.incident_id,
            device_id=incident.device_id or "unknown",
            attack_type=incident.attack_type.value,
            state=incident.state.value,
            reinvestigation_count=incident.reinvestigation_count,
        )


class AgentRunner:
    """Executes an :class:`AgentSpec` against an incident context package."""

    def __init__(
        self,
        registry: ToolRegistry,
        provider: LLMProvider,
        ids: IdFactory,
        clock: Clock,
        config: AgentConfig | None = None,
    ) -> None:
        self.registry = registry
        self.provider = provider
        self.ids = ids
        self.clock = clock
        self.config = config or AgentConfig()

    def run(
        self,
        spec: AgentSpec,
        package: IncidentContextPackage,
        risk_engine: Any | None = None,
        extra: dict[str, Any] | None = None,
        approval_sink: Any | None = None,
    ) -> AgentRunRecord:
        started_at = self.clock.now()
        wall_start = time.perf_counter()
        run_id = self.ids.agent_run()

        context = ToolContext(
            incident_id=package.incident.incident_id,
            incident_package=package,
            risk_engine=risk_engine,
            approval_sink=approval_sink,
            extra=dict(extra or {}),
        )

        tool_calls: list[ToolCallRecord] = []
        observations: list[tuple[str, dict[str, Any], Any]] = []
        validation_errors: list[str] = []
        attempts = 1
        status = AgentRunStatus.RUNNING
        structured: dict[str, Any] = {}
        error: str | None = None

        # Only tools the registry actually grants this role AND that are on
        # the spec's allowlist are advertised to the provider. A provider
        # cannot request what it is never shown, and the registry refuses it
        # even if it does.
        granted = {s.name for s in self.registry.tools_for_role(spec.role)} & spec.allowlist
        schemas = [
            s.json_schema() for s in self.registry.tools_for_role(spec.role) if s.name in granted
        ]

        for turn_index in range(self.config.max_turns):
            if time.perf_counter() - wall_start > self.config.timeout_seconds:
                status = AgentRunStatus.TIMED_OUT
                error = (
                    f"exceeded {self.config.timeout_seconds}s budget after "
                    f"{len(tool_calls)} tool calls"
                )
                break
            if len(tool_calls) >= self.config.max_tool_calls:
                status = AgentRunStatus.TIMED_OUT
                error = f"exceeded {self.config.max_tool_calls} tool-call budget"
                break

            turn = ProviderTurn(
                role=spec.role,
                system_prompt=spec.system_prompt,
                task_prompt=spec.task_prompt(package),
                tool_schemas=schemas,
                observations=list(observations),
                output_schema=schema_for(spec.role).model_json_schema(),
                turn_index=turn_index,
            )

            try:
                response = self.provider.respond(turn)
            except Exception as exc:
                status = AgentRunStatus.FAILED
                error = f"provider error: {type(exc).__name__}: {exc}"
                break

            if response.wants_tools:
                aborted = False
                for request in response.tool_calls:
                    try:
                        result = self.registry.call(
                            name=request.tool_name,
                            arguments=request.arguments,
                            context=context,
                            role=spec.role,
                            allowlist=spec.allowlist,
                        )
                    except AuthorityViolation as exc:
                        # Structural fault: abort, record, do not retry.
                        tool_calls.append(
                            ToolCallRecord(
                                tool_call_id=self.ids.tool_call(),
                                agent_role=spec.role,
                                tool_name=request.tool_name,
                                arguments=dict(request.arguments),
                                succeeded=False,
                                error=str(exc),
                                authority_violation=True,
                            )
                        )
                        status = AgentRunStatus.ABORTED_AUTHORITY
                        error = str(exc)
                        aborted = True
                        break
                    tool_calls.append(result.record)
                    observations.append(
                        (
                            request.tool_name,
                            dict(request.arguments),
                            result.value
                            if result.record.succeeded
                            else {"error": result.record.error},
                        )
                    )
                if aborted:
                    break
                continue

            # Provider returned a final answer: validate it.
            candidate = response.final_output or {}
            try:
                validated = schema_for(spec.role).model_validate(candidate)
                structured = validated.model_dump(mode="json")
                status = AgentRunStatus.SUCCEEDED
                break
            except Exception as exc:
                message = f"attempt {attempts}: {type(exc).__name__}: {exc}"
                validation_errors.append(message)
                if attempts > self.config.max_retries:
                    status = AgentRunStatus.VALIDATION_FAILED
                    error = (
                        f"structured output failed validation after {attempts} "
                        "attempts; output discarded rather than passed downstream"
                    )
                    structured = {}
                    break
                attempts += 1
                # Feed the error back as an observation so the provider can
                # correct itself rather than repeating the same mistake.
                observations.append(
                    (
                        "__validation_error__",
                        {},
                        {"error": str(exc), "attempt": attempts},
                    )
                )
                continue
        else:
            status = AgentRunStatus.TIMED_OUT
            error = f"exceeded {self.config.max_turns} turns without a final answer"

        findings = self._findings(structured)

        return AgentRunRecord(
            agent_run_id=run_id,
            incident_id=package.incident.incident_id,
            agent_role=spec.role,
            status=status,
            started_at=started_at,
            finished_at=self.clock.now(),
            provider=self.provider.name,
            model=self.provider.model,
            attempts=attempts,
            tool_calls=tool_calls,
            findings=findings,
            structured_output=structured,
            validation_errors=validation_errors,
            error=error,
        )

    @staticmethod
    def _findings(structured: dict[str, Any]) -> list[AgentFinding]:
        out: list[AgentFinding] = []
        for raw in structured.get("findings", []):
            try:
                out.append(
                    AgentFinding(
                        statement=str(raw["statement"]),
                        assertion_class=AssertionClass(raw["assertion_class"]),
                        confidence=float(raw.get("confidence", 0.5)),
                        supporting_evidence_ids=list(raw.get("supporting_evidence_ids", [])),
                    )
                )
            except (KeyError, ValueError):  # pragma: no cover - schema-guarded
                continue
        return out


__all__ = ["AgentConfig", "AgentRunner", "AgentSpec"]
