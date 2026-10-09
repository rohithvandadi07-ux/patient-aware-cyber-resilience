"""Agentic layer tests.

The authority-boundary tests are the most important here. The specification
requires that agents cannot bypass deterministic policy, cannot reach a
shell, and cannot escalate privilege. Those are claims about the
*implementation*, so they are tested by attempting the violations rather
than by inspecting prompts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agents import (
    ORCHESTRATOR_AUTHORITY,
    ROLE_AUTHORITY,
    AgentConfig,
    AgentRunner,
    AuthorityViolation,
    DeterministicProvider,
    build_provider,
    build_registry,
)
from agents.core.provider import ProviderResponse, ProviderTurn, ToolCallRequest
from agents.core.schemas import (
    InvestigationOutput,
    ResponsePlanningOutput,
)
from agents.specialists.definitions import (
    AGENTS_BY_ROLE,
    ALL_AGENTS,
    INVESTIGATION_SEQUENCE,
)
from agents.tools.registry import (
    ToolContext,
    ToolError,
    authority_rank,
)
from backend.app.domain.enums import (
    AgentRole,
    AgentRunStatus,
    AssertionClass,
    AttackType,
    DetectorKind,
    ResponseActionType,
    Severity,
    ToolAuthority,
)
from backend.app.domain.ids import Clock, IdFactory
from backend.app.domain.models import (
    DetectionResult,
    IncidentContextPackage,
)
from incident import IncidentService, InMemoryIncidentRepository
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import get_scenario
from risk_engine import PatientAwareRiskEngine

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


class SteppingClock(Clock):
    def __init__(self) -> None:
        self._t = T0

    def now(self) -> datetime:
        self._t += timedelta(seconds=1)
        return self._t


def _package(
    scenario: str = "s2_ventilator_compromise",
    ticks: int = 150,
    device_id: str = "VENT-ICU-01",
    attack: AttackType = AttackType.MALICIOUS_COMMAND,
    exhausted: list[ResponseActionType] | None = None,
) -> IncidentContextPackage:
    hospital = SmartHospital(scenario=get_scenario(scenario), ids=IdFactory(deterministic=True))
    events = hospital.run(ticks)
    detection = DetectionResult(
        detector_name="test_detector",
        detector_kind=DetectorKind.SUPERVISED_CLASSIFIER,
        timestamp=hospital.now,
        device_id=device_id,
        is_attack=True,
        attack_type=attack,
        confidence=0.9,
        severity=Severity.CRITICAL,
        anomaly_score=0.7,
    )
    service = IncidentService(
        repository=InMemoryIncidentRepository(),
        ids=IdFactory(deterministic=True),
        clock=SteppingClock(),
    )
    device_events = [e for e in events if e.device_id == device_id][-40:]
    incident, _ = service.ingest_detection(detection, events=device_events)
    return IncidentContextPackage(
        incident=incident,
        device_profile=hospital.profile(device_id),
        device_state=hospital.state(device_id),
        recent_events=device_events,
        exhausted_actions=exhausted or [],
    )


@pytest.fixture(scope="module")
def package() -> IncidentContextPackage:
    return _package()


@pytest.fixture
def runner() -> AgentRunner:
    ids = IdFactory(deterministic=True)
    return AgentRunner(
        registry=build_registry(ids),
        provider=build_provider(),
        ids=ids,
        clock=SteppingClock(),
    )


@pytest.fixture(scope="module")
def engine() -> PatientAwareRiskEngine:
    return PatientAwareRiskEngine()


# ===========================================================================
# Authority boundary - the architectural claim
# ===========================================================================
class TestAuthorityBoundary:
    def test_no_agent_role_can_reach_an_actuating_tool(self) -> None:
        """The central safety property.

        Every role tops out at COMPUTE, so actuation, approval requests and
        ledger writes are reachable by no agent. They are performed by the
        orchestrator after the policy engine rules.
        """
        registry = build_registry(IdFactory(deterministic=True))
        privileged = {
            name
            for name in registry.names()
            if authority_rank(registry.spec(name).authority) > authority_rank(ToolAuthority.COMPUTE)
        }
        assert privileged, "there should be privileged tools to protect"
        for role in AgentRole:
            reachable = {s.name for s in registry.tools_for_role(role)}
            assert not (reachable & privileged), (
                f"{role.value} can reach privileged tools {sorted(reachable & privileged)}"
            )

    def test_every_role_ceiling_is_at_most_compute(self) -> None:
        for role, ceiling in ROLE_AUTHORITY.items():
            assert authority_rank(ceiling) <= authority_rank(ToolAuthority.COMPUTE), (
                f"{role.value} has ceiling {ceiling.value}, above COMPUTE"
            )

    def test_orchestrator_ceiling_is_above_every_agent(self) -> None:
        for ceiling in ROLE_AUTHORITY.values():
            assert authority_rank(ORCHESTRATOR_AUTHORITY) > authority_rank(ceiling)

    def test_calling_an_actuating_tool_raises(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        context = ToolContext(
            incident_id=package.incident.incident_id,
            incident_package=package,
            risk_engine=engine,
        )
        with pytest.raises(AuthorityViolation, match="cannot escalate"):
            registry.call(
                name="propose_safe_action",
                arguments={"action_type": "shutdown_device"},
                context=context,
                role=AgentRole.RESPONSE_PLANNING,
            )

    def test_off_allowlist_tool_raises(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        context = ToolContext(
            incident_id=package.incident.incident_id,
            incident_package=package,
            risk_engine=engine,
        )
        with pytest.raises(AuthorityViolation, match="not on"):
            registry.call(
                name="get_telemetry",
                arguments={},
                context=context,
                role=AgentRole.INVESTIGATION,
                allowlist=frozenset({"get_incident"}),
            )

    def test_unknown_tool_raises(self, package) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        context = ToolContext(incident_id="INC-1", incident_package=package)
        with pytest.raises(AuthorityViolation, match="unknown tool"):
            registry.call(
                name="run_shell_command",
                arguments={"cmd": "rm -rf /"},
                context=context,
                role=AgentRole.INVESTIGATION,
            )

    def test_wrong_role_for_tool_raises(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        context = ToolContext(incident_id="INC-1", incident_package=package, risk_engine=engine)
        with pytest.raises(AuthorityViolation, match="not available to"):
            registry.call(
                name="verify_recovery",
                arguments={},
                context=context,
                role=AgentRole.INVESTIGATION,
            )

    def test_there_is_no_shell_or_filesystem_tool(self) -> None:
        """A capability that does not exist cannot be misused.

        Matched on whole underscore-separated words so that legitimate
        names such as ``evaluate_candidate_actions`` are not flagged for
        containing "eval" as a substring.
        """
        registry = build_registry(IdFactory(deterministic=True))
        forbidden_words = {
            "shell",
            "bash",
            "sh",
            "cmd",
            "command",
            "exec",
            "execute",
            "eval",
            "system",
            "subprocess",
            "spawn",
            "popen",
            "file",
            "files",
            "path",
            "dir",
            "glob",
            "read",
            "write",
            "delete",
            "open",
            "http",
            "https",
            "url",
            "fetch",
            "curl",
            "download",
            "sql",
            "db",
            "database",
            "import",
            "pickle",
        }
        # Whitelisted names whose words are unavoidable and whose
        # implementation is a pure read over the context package.
        allowed_exceptions = {"get_security_logs"}
        for name in registry.names():
            if name in allowed_exceptions:
                continue
            words = set(name.lower().split("_"))
            offending = words & forbidden_words
            assert not offending, (
                f"tool {name!r} contains {sorted(offending)}, suggesting an uncontrolled capability"
            )

    def test_no_tool_implementation_touches_io(self) -> None:
        """Static check: tool implementations must not import I/O modules."""
        import inspect

        from agents.tools import builtin

        source = inspect.getsource(builtin)
        for banned in (
            "import os",
            "import subprocess",
            "import socket",
            "import requests",
            "import httpx",
            "open(",
            "eval(",
            "exec(",
            "__import__",
        ):
            assert banned not in source, (
                f"the tool module contains {banned!r}; tools must be pure "
                "functions over the read-only context"
            )

    def test_authority_violation_aborts_the_run(self, package, engine) -> None:
        """A violation is structural: abort and record, never retry around."""

        class RogueProvider(DeterministicProvider):
            def respond(self, turn: ProviderTurn) -> ProviderResponse:
                return ProviderResponse(
                    tool_calls=[
                        ToolCallRequest(
                            tool_name="propose_safe_action",
                            arguments={"action_type": "shutdown_device"},
                        )
                    ],
                    model=self.model,
                )

        ids = IdFactory(deterministic=True)
        runner = AgentRunner(
            registry=build_registry(ids),
            provider=RogueProvider(),
            ids=ids,
            clock=SteppingClock(),
        )
        record = runner.run(
            AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], package, risk_engine=engine
        )
        assert record.status is AgentRunStatus.ABORTED_AUTHORITY
        assert any(c.authority_violation for c in record.tool_calls)
        assert record.structured_output == {}

    def test_agent_cannot_supply_its_own_authority_override(self, package, engine) -> None:
        """The loop never forwards an override, so an agent cannot elevate."""
        import inspect

        from agents.core import loop

        source = inspect.getsource(loop.AgentRunner.run)
        assert "authority_override" not in source, (
            "the agent loop must never pass authority_override; only the orchestrator may elevate"
        )


# ===========================================================================
# Tool behaviour
# ===========================================================================
class TestTools:
    def _ctx(self, package, engine) -> ToolContext:
        return ToolContext(
            incident_id=package.incident.incident_id,
            incident_package=package,
            risk_engine=engine,
        )

    def test_telemetry_strips_the_simulator_truth_channel(self, package, engine) -> None:
        """Agents must reason from reported values, as a clinician would."""
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_telemetry",
            {"limit": 5},
            self._ctx(package, engine),
            AgentRole.INVESTIGATION,
        )
        assert result.record.succeeded
        for event in result.value["events"]:
            leaked = [k for k in event["measurements"] if k.startswith("truth_")]
            assert not leaked, f"simulator truth channel leaked to agent: {leaked}"

    def test_telemetry_warns_that_values_may_be_spoofed(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_telemetry", {}, self._ctx(package, engine), AgentRole.INVESTIGATION
        )
        assert "spoof" in result.value["_note"].lower()

    def test_risk_tools_report_the_deterministic_result(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "calculate_clinical_risk",
            {},
            self._ctx(package, engine),
            AgentRole.HEALTHCARE_CONTEXT,
        )
        authoritative = engine.clinical_risk(package.device_profile, package.device_state)
        assert result.value["score"] == authoritative.score
        assert "authoritative" in result.value["_note"]

    def test_no_tool_can_write_a_risk_score(self) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        for name in registry.names():
            spec = registry.spec(name)
            assert not name.startswith(("set_", "write_", "override_", "update_")), (
                f"tool {name!r} appears to mutate state"
            )
            assert "risk" not in set(spec.arguments) or name.startswith(("calculate_", "evaluate_"))

    def test_batched_evaluation_returns_every_action(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "evaluate_candidate_actions",
            {},
            self._ctx(package, engine),
            AgentRole.RESPONSE_PLANNING,
        )
        assert result.record.succeeded
        returned = {c["action_type"] for c in result.value["candidates"]}
        assert returned == {a.value for a in ResponseActionType}

    def test_batched_evaluation_marks_unsafe_as_inadmissible(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "evaluate_candidate_actions",
            {},
            self._ctx(package, engine),
            AgentRole.RESPONSE_PLANNING,
        )
        shutdown = next(
            c for c in result.value["candidates"] if c["action_type"] == "shutdown_device"
        )
        assert shutdown["impact_class"] == "unsafe"
        assert shutdown["admissible"] is False

    def test_exhausted_actions_are_marked(self, engine) -> None:
        pkg = _package(exhausted=[ResponseActionType.BLOCK_SOURCE_TRAFFIC])
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "evaluate_candidate_actions",
            {},
            self._ctx(pkg, engine),
            AgentRole.RESPONSE_PLANNING,
        )
        row = next(
            c for c in result.value["candidates"] if c["action_type"] == "block_source_traffic"
        )
        assert row["already_attempted"] is True
        assert row["admissible"] is False

    def test_propose_safe_action_does_not_execute(self, package, engine) -> None:
        """Named per spec, but deliberately narrower: it only proposes."""
        from agents.tools.builtin import propose_safe_action

        result = propose_safe_action(
            self._ctx(package, engine), {"action_type": "block_source_traffic"}
        )
        assert result["executed"] is False
        assert result["status"] == "proposed"
        assert "NOT executed" in result["_note"]

    def test_approval_request_requires_a_substantive_justification(self, package, engine) -> None:
        from agents.tools.builtin import request_human_approval

        with pytest.raises(ToolError, match="substantive"):
            request_human_approval(
                self._ctx(package, engine),
                {"action_type": "shutdown_device", "justification": "do it"},
            )

    def test_bad_arguments_are_rejected_before_dispatch(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_telemetry",
            {"limit": "not-an-int"},
            self._ctx(package, engine),
            AgentRole.INVESTIGATION,
        )
        assert result.record.succeeded is False
        assert "must be int" in (result.record.error or "")

    def test_unknown_argument_is_rejected(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_incident",
            {"injected": "payload"},
            self._ctx(package, engine),
            AgentRole.INVESTIGATION,
        )
        assert result.record.succeeded is False
        assert "unknown arguments" in (result.record.error or "")

    def test_tool_error_is_recorded_not_raised(self, package) -> None:
        """A tool failure is an observation the agent can work around."""
        registry = build_registry(IdFactory(deterministic=True))
        context = ToolContext(incident_id="INC-1", incident_package=package, risk_engine=None)
        result = registry.call("calculate_cyber_risk", {}, context, AgentRole.THREAT_REASONING)
        assert result.record.succeeded is False
        assert "risk engine" in (result.record.error or "")

    def test_clinical_context_declares_data_as_synthetic(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_clinical_context",
            {},
            self._ctx(package, engine),
            AgentRole.HEALTHCARE_CONTEXT,
        )
        assert result.value["patient"]["synthetic"] is True
        assert "SYNTHETIC" in result.value["_note"]

    def test_every_call_is_audited(self, package, engine) -> None:
        registry = build_registry(IdFactory(deterministic=True))
        result = registry.call(
            "get_incident", {}, self._ctx(package, engine), AgentRole.INVESTIGATION
        )
        record = result.record
        assert record.tool_call_id
        assert record.tool_name == "get_incident"
        assert record.duration_ms >= 0.0
        assert record.result_digest


# ===========================================================================
# Output validation
# ===========================================================================
class TestOutputValidation:
    def test_finding_without_epistemic_status_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="assertion_class"):
            InvestigationOutput(findings=[{"statement": "something happened"}])

    def test_invalid_epistemic_status_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="assertion_class"):
            InvestigationOutput(findings=[{"statement": "x", "assertion_class": "probably"}])

    def test_cannot_verify_more_evidence_than_reviewed(self) -> None:
        with pytest.raises(ValueError, match="cannot verify"):
            InvestigationOutput(evidence_reviewed=2, evidence_verified=9)

    def test_cannot_propose_an_unsafe_candidate(self) -> None:
        with pytest.raises(ValueError, match="UNSAFE"):
            ResponsePlanningOutput(
                candidate_actions=[{"action_type": "shutdown_device", "impact_class": "unsafe"}]
            )

    def test_confidence_must_be_in_range(self) -> None:
        with pytest.raises(ValueError):
            InvestigationOutput(
                findings=[
                    {
                        "statement": "x",
                        "assertion_class": "observed_fact",
                        "confidence": 2.0,
                    }
                ]
            )

    def test_unknown_action_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            ResponsePlanningOutput(recommended_action="delete_the_patient")

    def test_invalid_output_is_retried_then_discarded(self, package, engine) -> None:
        """Malformed agent output must never reach the risk engine."""

        class BrokenProvider(DeterministicProvider):
            def respond(self, turn: ProviderTurn) -> ProviderResponse:
                return ProviderResponse(
                    final_output={"findings": [{"statement": "x", "assertion_class": "nope"}]},
                    model=self.model,
                )

        ids = IdFactory(deterministic=True)
        runner = AgentRunner(
            registry=build_registry(ids),
            provider=BrokenProvider(),
            ids=ids,
            clock=SteppingClock(),
            config=AgentConfig(max_retries=2),
        )
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert record.status is AgentRunStatus.VALIDATION_FAILED
        assert record.attempts == 3
        assert len(record.validation_errors) == 3
        assert record.structured_output == {}


# ===========================================================================
# The loop
# ===========================================================================
class TestAgentLoop:
    def test_each_agent_succeeds_on_a_real_incident(self, package, runner, engine) -> None:
        for role in INVESTIGATION_SEQUENCE:
            record = runner.run(AGENTS_BY_ROLE[role], package, risk_engine=engine)
            assert record.status is AgentRunStatus.SUCCEEDED, f"{role.value} failed: {record.error}"
            assert record.findings, f"{role.value} produced no findings"
            assert record.tool_calls, f"{role.value} made no tool calls"

    def test_agents_are_genuinely_multi_step(self, package, runner, engine) -> None:
        """Not prompt-and-answer: evidence is gathered across turns."""
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert len(record.tool_calls) >= 5
        assert len({c.tool_name for c in record.tool_calls}) >= 5

    def test_tool_budget_is_sufficient_for_the_planned_sequence(
        self, package, runner, engine
    ) -> None:
        """Regression: planning once exceeded its budget and produced nothing."""
        record = runner.run(
            AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], package, risk_engine=engine
        )
        assert record.status is AgentRunStatus.SUCCEEDED
        assert len(record.tool_calls) < runner.config.max_tool_calls

    def test_budget_overrun_times_out_cleanly(self, package, engine) -> None:
        ids = IdFactory(deterministic=True)
        runner = AgentRunner(
            registry=build_registry(ids),
            provider=build_provider(),
            ids=ids,
            clock=SteppingClock(),
            config=AgentConfig(max_tool_calls=2),
        )
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert record.status is AgentRunStatus.TIMED_OUT
        assert "budget" in (record.error or "")

    def test_provider_failure_is_recorded_not_raised(self, package, engine) -> None:
        class ExplodingProvider(DeterministicProvider):
            def respond(self, turn: ProviderTurn) -> ProviderResponse:
                raise RuntimeError("provider unreachable")

        ids = IdFactory(deterministic=True)
        runner = AgentRunner(
            registry=build_registry(ids),
            provider=ExplodingProvider(),
            ids=ids,
            clock=SteppingClock(),
        )
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert record.status is AgentRunStatus.FAILED
        assert "provider unreachable" in (record.error or "")

    def test_runs_are_reproducible(self, package, engine) -> None:
        def once() -> dict:
            ids = IdFactory(deterministic=True)
            runner = AgentRunner(
                registry=build_registry(ids),
                provider=build_provider(),
                ids=ids,
                clock=SteppingClock(),
            )
            return runner.run(
                AGENTS_BY_ROLE[AgentRole.THREAT_REASONING], package, risk_engine=engine
            ).structured_output

        assert once() == once()

    def test_record_captures_provider_identity(self, package, runner, engine) -> None:
        """Every result must be attributable to the provider that produced it."""
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert record.provider == "deterministic"
        assert record.model == "deterministic-planner-v1"


# ===========================================================================
# Specialist behaviour
# ===========================================================================
class TestSpecialists:
    def test_investigation_reports_observed_facts(self, package, runner, engine) -> None:
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert any(f.assertion_class is AssertionClass.OBSERVED_FACT for f in record.findings)

    def test_investigation_does_not_recommend(self, package, runner, engine) -> None:
        """Role separation: investigation gathers, it does not propose."""
        record = runner.run(AGENTS_BY_ROLE[AgentRole.INVESTIGATION], package, risk_engine=engine)
        assert not any(f.assertion_class is AssertionClass.RECOMMENDATION for f in record.findings)

    def test_threat_reasoning_labels_detector_output_as_inference(
        self, package, runner, engine
    ) -> None:
        record = runner.run(AGENTS_BY_ROLE[AgentRole.THREAT_REASONING], package, risk_engine=engine)
        detector_findings = [f for f in record.findings if "classified" in f.statement]
        assert detector_findings
        assert all(f.assertion_class is AssertionClass.INFERENCE for f in detector_findings)

    def test_healthcare_context_identifies_life_support(self, package, runner, engine) -> None:
        record = runner.run(
            AGENTS_BY_ROLE[AgentRole.HEALTHCARE_CONTEXT], package, risk_engine=engine
        )
        out = record.structured_output
        assert out["life_support_involved"] is True
        assert out["device_criticality"] == "life_sustaining"
        assert out["safety_constraints"]

    def test_planning_never_recommends_an_unsafe_action(self, package, runner, engine) -> None:
        record = runner.run(
            AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], package, risk_engine=engine
        )
        out = record.structured_output
        assert out["recommended_action"] not in {
            "shutdown_device",
            "isolate_network_segment",
        }
        for candidate in out["candidate_actions"]:
            assert candidate["impact_class"] != "unsafe"

    def test_planning_requires_approval_on_a_life_critical_device(
        self, package, runner, engine
    ) -> None:
        record = runner.run(
            AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], package, risk_engine=engine
        )
        assert record.structured_output["requires_human_approval"] is True

    def test_planning_permits_autonomy_on_a_noncritical_asset(self, runner, engine) -> None:
        """Patient-awareness must not mean paralysis everywhere."""
        pkg = _package(
            scenario="s1_noncritical_compromise",
            ticks=130,
            device_id="WS-NURSE-01",
            attack=AttackType.RANSOMWARE_BEHAVIOUR,
        )
        record = runner.run(AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], pkg, risk_engine=engine)
        out = record.structured_output
        assert out["requires_human_approval"] is False
        assert out["recommended_action"] != "escalate_to_clinical_staff"

    def test_planning_excludes_an_exhausted_action(self, runner, engine) -> None:
        """Mandated scenario 3: re-planning must choose differently."""
        pkg = _package(
            scenario="s3_recovery_failure",
            ticks=120,
            device_id="PUMP-ICU-01",
            attack=AttackType.UNAUTHORIZED_ACCESS,
            exhausted=[ResponseActionType.BLOCK_SOURCE_TRAFFIC],
        )
        record = runner.run(AGENTS_BY_ROLE[AgentRole.RESPONSE_PLANNING], pkg, risk_engine=engine)
        out = record.structured_output
        assert out["recommended_action"] != "block_source_traffic"
        proposed = {c["action_type"] for c in out["candidate_actions"]}
        assert "block_source_traffic" not in proposed
        rejected = {r["action_type"] for r in out["rejected_actions"]}
        assert "block_source_traffic" in rejected

    def test_every_specialist_declares_a_fixed_allowlist(self) -> None:
        for spec in ALL_AGENTS:
            assert spec.allowlist
            assert isinstance(spec.allowlist, frozenset), (
                "an allowlist must be immutable so it cannot be extended at run time"
            )

    def test_every_prompt_states_the_authority_boundary(self) -> None:
        """Defence in depth: the registry enforces it, the prompt states it."""
        for spec in ALL_AGENTS:
            prompt = spec.system_prompt.lower()
            assert "authority boundary" in prompt
            assert "deterministic" in prompt
            assert "observed_fact" in prompt


# ===========================================================================
# Provider abstraction
# ===========================================================================
class TestProviders:
    def test_default_is_deterministic_and_needs_no_key(self) -> None:
        provider = build_provider()
        assert provider.is_deterministic is True
        assert provider.name == "deterministic"

    def test_unknown_provider_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown provider"):
            build_provider("gpt-9000")

    def test_anthropic_provider_requires_a_key(self, monkeypatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            build_provider("anthropic")

    def test_deterministic_provider_is_seed_reproducible(self, package) -> None:
        turn = ProviderTurn(
            role=AgentRole.INVESTIGATION,
            system_prompt="s",
            task_prompt="t",
            tool_schemas=[{"name": "get_incident"}],
        )
        a = DeterministicProvider(seed=7).respond(turn)
        b = DeterministicProvider(seed=7).respond(turn)
        assert a.tool_calls[0].tool_name == b.tool_calls[0].tool_name

    def test_json_extraction_handles_surrounding_prose(self) -> None:
        from agents.core.provider import _extract_json

        text = 'Here is my analysis.\n{"findings": [], "attack_type": "dos"}\nDone.'
        assert _extract_json(text) == {"findings": [], "attack_type": "dos"}

    def test_json_extraction_returns_none_without_json(self) -> None:
        from agents.core.provider import _extract_json

        assert _extract_json("no json here at all") is None
