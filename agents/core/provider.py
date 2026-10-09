"""LLM provider abstraction with a deterministic offline provider.

Two reasons this abstraction exists rather than a direct API call.

**Reproducibility.** An experiment whose results depend on a hosted model's
behaviour at a particular moment is not reproducible, and a paper reporting
such numbers cannot be checked. The deterministic provider makes the whole
closed loop runnable offline with byte-identical output for a given seed,
so every structural claim about the platform is verifiable without an API
key. Results obtained with a real LLM are reported separately, with model
versions, seeds and across-run variance.

**Honesty about what the agents contribute.** Running the pipeline with the
deterministic provider is itself an ablation: it isolates how much of the
system's behaviour comes from the orchestration and deterministic engines
versus from the language model. That comparison belongs in the paper, and
it is only possible if both can run.

The deterministic provider is a rule-based planner, not a model. It is not
presented as one, and the evaluation labels every run with the provider
that produced it.
"""

from __future__ import annotations

import json
import os
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.app.domain.enums import AgentRole


@dataclass
class ToolCallRequest:
    """A provider's request to invoke one tool."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResponse:
    """One turn of a provider's output.

    Either it requests tool calls, or it returns a final structured answer.
    """

    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    final_output: dict[str, Any] | None = None
    raw_text: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls) and self.final_output is None


@dataclass
class ProviderTurn:
    """What the agent loop sends to the provider each turn."""

    role: AgentRole
    system_prompt: str
    task_prompt: str
    tool_schemas: list[dict[str, Any]]
    #: (tool_name, arguments, result) for every call made so far.
    observations: list[tuple[str, dict[str, Any], Any]] = field(default_factory=list)
    output_schema: dict[str, Any] | None = None
    turn_index: int = 0


class LLMProvider(ABC):
    """Interface every provider implements."""

    name: str = "abstract"
    model: str = "abstract"

    @abstractmethod
    def respond(self, turn: ProviderTurn) -> ProviderResponse: ...

    @property
    def is_deterministic(self) -> bool:
        return False


# ===========================================================================
# Deterministic provider
# ===========================================================================
#: Investigation plan per role: the tools to gather, in order, before
#: producing a structured conclusion. This encodes the evidence-gathering
#: discipline the specification requires of each agent.
ROLE_PLAN: dict[AgentRole, tuple[str, ...]] = {
    AgentRole.INVESTIGATION: (
        "get_incident",
        "get_device_profile",
        "get_device_state",
        "get_telemetry",
        "get_network_events",
        "get_security_logs",
        "get_attack_evidence",
        "get_timeline",
    ),
    AgentRole.THREAT_REASONING: (
        "get_incident",
        "get_attack_evidence",
        "get_network_events",
        "get_security_logs",
        "calculate_cyber_risk",
    ),
    AgentRole.HEALTHCARE_CONTEXT: (
        "get_device_profile",
        "get_clinical_context",
        "get_device_state",
        "calculate_clinical_risk",
    ),
    AgentRole.RESPONSE_PLANNING: (
        "get_incident",
        "get_exhausted_actions",
        "calculate_cyber_risk",
        "calculate_clinical_risk",
        # One batched comparison rather than a call per candidate.
        "evaluate_candidate_actions",
    ),
    AgentRole.RECOVERY_VERIFICATION: (
        "get_device_state",
        "get_telemetry",
        "get_network_events",
        "verify_recovery",
        "calculate_cyber_risk",
    ),
}


class DeterministicProvider(LLMProvider):
    """Rule-based planner. No model, no network, no API key.

    Walks the role's tool plan, then synthesises a structured output from
    the observations it gathered. Output is a pure function of the
    observations and the seed, so a scenario replays identically.
    """

    name = "deterministic"

    def __init__(self, seed: int = 20260101) -> None:
        self.model = "deterministic-planner-v1"
        self.seed = seed
        self._rng = random.Random(seed)  # noqa: S311 - not security-sensitive

    @property
    def is_deterministic(self) -> bool:
        return True

    def respond(self, turn: ProviderTurn) -> ProviderResponse:
        called = {name for name, _, _ in turn.observations}
        plan = ROLE_PLAN.get(turn.role, ())
        available = {s["name"] for s in turn.tool_schemas}

        # Request the next planned tool that is available and not yet called.
        for tool in plan:
            if tool in called or tool not in available:
                continue
            return ProviderResponse(
                tool_calls=[ToolCallRequest(tool_name=tool, arguments=self._args(tool))],
                model=self.model,
                raw_text=f"[deterministic] gathering {tool}",
            )

        return ProviderResponse(
            final_output=self._synthesise(turn),
            model=self.model,
            raw_text="[deterministic] synthesising structured output",
        )

    # -- helpers -----------------------------------------------------------
    def _args(self, tool: str) -> dict[str, Any]:
        if tool in {"get_telemetry", "get_network_events", "get_security_logs"}:
            return {"limit": 20}
        if tool == "get_timeline":
            return {"limit": 25}
        return {}

    #: Candidate actions the deterministic planner considers, ordered so the
    #: cheapest effective options are evaluated first.
    CANDIDATES: tuple[str, ...] = (
        "monitor_only",
        "block_source_traffic",
        "rate_limit_traffic",
        "revoke_session",
        "rotate_credentials",
        "restrict_communication",
        "quarantine_device",
        "isolate_network_segment",
        "activate_backup_path",
        "failover_to_redundant_device",
        "restart_device_service",
        "shutdown_device",
        "escalate_to_clinical_staff",
    )

    @staticmethod
    def _exhausted(turn: ProviderTurn) -> set[str]:
        for name, _, result in turn.observations:
            if name == "get_exhausted_actions" and isinstance(result, dict):
                return set(result.get("exhausted_actions", []))
        return set()

    @staticmethod
    def _observation(turn: ProviderTurn, tool: str) -> Any:
        for name, _, result in turn.observations:
            if name == tool:
                return result
        return None

    def _synthesise(self, turn: ProviderTurn) -> dict[str, Any]:
        """Build the role's structured output from gathered observations.

        Findings are tagged with their epistemic status: values read from
        telemetry or device state are OBSERVED_FACT, interpretations are
        INFERENCE, proposals are RECOMMENDATION. The deterministic provider
        is held to the same discipline as an LLM, so the ablation compares
        like with like.
        """
        if turn.role is AgentRole.INVESTIGATION:
            return self._investigation(turn)
        if turn.role is AgentRole.THREAT_REASONING:
            return self._threat(turn)
        if turn.role is AgentRole.HEALTHCARE_CONTEXT:
            return self._healthcare(turn)
        if turn.role is AgentRole.RESPONSE_PLANNING:
            return self._planning(turn)
        if turn.role is AgentRole.RECOVERY_VERIFICATION:
            return self._recovery(turn)
        return {"findings": []}

    def _investigation(self, turn: ProviderTurn) -> dict[str, Any]:
        incident = self._observation(turn, "get_incident") or {}
        state = self._observation(turn, "get_device_state") or {}
        telemetry = self._observation(turn, "get_telemetry") or {}
        network = self._observation(turn, "get_network_events") or {}
        logs = self._observation(turn, "get_security_logs") or {}
        evidence = self._observation(turn, "get_attack_evidence") or {}

        findings: list[dict[str, Any]] = []
        affected: list[str] = []
        if incident.get("device_id"):
            affected.append(str(incident["device_id"]))

        if state:
            findings.append(
                {
                    "statement": (
                        f"Device {state.get('device_id')} is in state "
                        f"{state.get('operational_state')} with network state "
                        f"{state.get('network_state')}; alarm="
                        f"{state.get('alarm_active')} "
                        f"({state.get('alarm_reason') or 'none'}); fault codes "
                        f"{state.get('fault_codes') or 'none'}"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )
        if state.get("fault_codes"):
            findings.append(
                {
                    "statement": (
                        f"Fault codes present ({', '.join(state['fault_codes'])}), "
                        "indicating the device itself has detected a problem"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )

        # Identify attacker-side identities from the events gathered.
        identities: set[str] = set()
        for bundle in (network, logs):
            for ev in bundle.get("events", []):
                if ev.get("source_ip"):
                    identities.add(str(ev["source_ip"]))
        if identities:
            findings.append(
                {
                    "statement": (
                        f"Traffic observed from source addresses {sorted(identities)[:5]}"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )

        # Unauthenticated commands are the strongest single observable.
        unauth = [
            ev
            for ev in logs.get("events", [])
            if ev.get("measurements", {}).get("authenticated_session") == 0.0
        ]
        if unauth:
            findings.append(
                {
                    "statement": (
                        f"{len(unauth)} device command(s) arrived without an authenticated session"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )

        verified = [e for e in evidence.get("evidence", []) if e.get("verified")]
        return {
            "findings": findings,
            "affected_assets": affected,
            "evidence_reviewed": len(evidence.get("evidence", [])),
            "evidence_verified": len(verified),
            "telemetry_samples": telemetry.get("count", 0),
            "network_records": network.get("count", 0),
            "security_events": logs.get("count", 0),
            "source_identities": sorted(identities),
            "timeline_reconstructed": bool(self._observation(turn, "get_timeline")),
        }

    def _threat(self, turn: ProviderTurn) -> dict[str, Any]:
        incident = self._observation(turn, "get_incident") or {}
        risk = self._observation(turn, "calculate_cyber_risk") or {}
        detection = incident.get("detection") or {}
        attack = detection.get("attack_type") or incident.get("attack_type") or "unknown"
        findings = [
            {
                "statement": (
                    f"Detector {detection.get('detector', 'unknown')} classified "
                    f"this as {attack} with confidence "
                    f"{detection.get('confidence', 0.0):.2f}"
                ),
                "assertion_class": "inference",
                "confidence": float(detection.get("confidence", 0.0)),
            }
        ]
        if risk:
            findings.append(
                {
                    "statement": (
                        f"Deterministic cyber risk {risk.get('score', 0.0):.2f} "
                        f"({risk.get('band')}), uncertainty "
                        f"{risk.get('uncertainty', 0.0):.2f}"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )
            top = max(
                risk.get("factors", []),
                key=lambda f: f.get("contribution", 0.0),
                default=None,
            )
            if top:
                findings.append(
                    {
                        "statement": (
                            f"Dominant risk factor: {top['name']} "
                            f"({top['contribution']:.2f}) - {top['rationale']}"
                        ),
                        "assertion_class": "inference",
                        "confidence": 0.8,
                    }
                )
        return {
            "findings": findings,
            "attack_type": attack,
            "severity": incident.get("severity", "medium"),
            "confidence": float(detection.get("confidence", 0.0)),
            "cyber_risk_score": risk.get("score"),
            "propagation_risk": next(
                (
                    f["value"]
                    for f in risk.get("factors", [])
                    if f["name"] == "propagation_potential"
                ),
                None,
            ),
            "persistence": next(
                (f["value"] for f in risk.get("factors", []) if f["name"] == "persistence"),
                None,
            ),
        }

    def _healthcare(self, turn: ProviderTurn) -> dict[str, Any]:
        profile = self._observation(turn, "get_device_profile") or {}
        clinical = self._observation(turn, "get_clinical_context") or {}
        risk = self._observation(turn, "calculate_clinical_risk") or {}
        patient = clinical.get("patient") or {}
        findings = [
            {
                "statement": (
                    f"{profile.get('device_type')} classified "
                    f"{profile.get('criticality')}; life-support relevant="
                    f"{profile.get('life_support_relevant')}; redundant peer="
                    f"{profile.get('has_redundant_peer')}"
                ),
                "assertion_class": "observed_fact",
                "confidence": 1.0,
            }
        ]
        if patient:
            findings.append(
                {
                    "statement": (
                        f"Synthetic patient {patient.get('patient_ref')} has "
                        f"{patient.get('dependency')} dependency at acuity "
                        f"{patient.get('acuity')}; on life support="
                        f"{patient.get('on_life_support')}; tolerable "
                        f"interruption {patient.get('tolerable_interruption_minutes')} min"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )
        if risk:
            findings.append(
                {
                    "statement": (
                        f"Deterministic clinical risk {risk.get('score', 0.0):.2f} "
                        f"({risk.get('band')}). {risk.get('explanation', '')}"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )
        constraints: list[str] = []
        if risk.get("life_support_involved"):
            constraints.append(
                "device is sustaining life support: actions that interrupt "
                "therapy are unsafe unless a validated failover exists"
            )
        if not profile.get("has_redundant_peer"):
            constraints.append("no redundant peer: no safe clinical alternative")
        if float(profile.get("acceptable_interruption_seconds", 0.0)) <= 0.0:
            constraints.append("zero tolerable interruption for this device")
        return {
            "findings": findings,
            "device_criticality": profile.get("criticality"),
            "patient_dependency": risk.get("patient_dependency") or patient.get("dependency"),
            "life_support_involved": bool(risk.get("life_support_involved")),
            "clinical_risk_score": risk.get("score"),
            "safety_constraints": constraints,
        }

    def _planning(self, turn: ProviderTurn) -> dict[str, Any]:
        cyber = self._observation(turn, "calculate_cyber_risk") or {}
        clinical = self._observation(turn, "calculate_clinical_risk") or {}
        exhausted = self._exhausted(turn)
        batch = self._observation(turn, "evaluate_candidate_actions") or {}
        impacts = [(row.get("action_type"), row) for row in batch.get("candidates", [])]
        # Fall back to per-action calls if a provider used them instead.
        impacts.extend(
            (args.get("action_type"), result)
            for name, args, result in turn.observations
            if name == "evaluate_response_impact" and isinstance(result, dict)
        )

        admissible = [
            (action, r)
            for action, r in impacts
            if r.get("impact_class") != "unsafe" and action not in exhausted
        ]
        # Rank by the same shape the deterministic engine uses, so the
        # agent's proposal ordering is coherent with the authoritative
        # decision rather than arbitrary.
        ranked = sorted(
            admissible,
            key=lambda pair: (
                float(pair[1].get("security_benefit", 0.0))
                - float(pair[1].get("clinical_impact", 0.0))
            ),
            reverse=True,
        )
        rejected = [
            {
                "action_type": action,
                "reason": (
                    "already attempted without achieving recovery"
                    if action in exhausted
                    else f"impact class {r.get('impact_class')}"
                ),
            }
            for action, r in impacts
            if (action, r) not in admissible
        ]

        findings = [
            {
                "statement": (
                    f"Evaluated {len(impacts)} candidate actions; "
                    f"{len(admissible)} admissible, {len(rejected)} rejected"
                ),
                "assertion_class": "observed_fact",
                "confidence": 1.0,
            }
        ]
        if ranked:
            best, best_impact = ranked[0]
            findings.append(
                {
                    "statement": (
                        f"Recommend {best}: security benefit "
                        f"{best_impact.get('security_benefit', 0.0):.2f} against "
                        f"clinical cost {best_impact.get('clinical_impact', 0.0):.2f} "
                        f"(impact {best_impact.get('impact_class')})"
                    ),
                    "assertion_class": "recommendation",
                    "confidence": 0.75,
                }
            )
        if exhausted:
            findings.append(
                {
                    "statement": (f"Excluded previously-failed actions: {sorted(exhausted)}"),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )

        return {
            "findings": findings,
            "candidate_actions": [
                {
                    "action_type": action,
                    "security_benefit": r.get("security_benefit"),
                    "clinical_impact": r.get("clinical_impact"),
                    "impact_class": r.get("impact_class"),
                    "rationale": r.get("explanation", ""),
                }
                for action, r in ranked
            ],
            "rejected_actions": rejected,
            "recommended_action": ranked[0][0] if ranked else "escalate_to_clinical_staff",
            "requires_human_approval": bool(
                clinical.get("life_support_involved") or float(clinical.get("score", 0.0)) >= 0.6
            ),
            "cyber_risk_score": cyber.get("score"),
            "clinical_risk_score": clinical.get("score"),
        }

    def _recovery(self, turn: ProviderTurn) -> dict[str, Any]:
        state = self._observation(turn, "get_device_state") or {}
        verification = self._observation(turn, "verify_recovery") or {}
        cyber = self._observation(turn, "calculate_cyber_risk") or {}
        findings = [
            {
                "statement": (
                    f"Post-response device state: "
                    f"{state.get('operational_state')} / "
                    f"{state.get('network_state')}; therapy delivering="
                    f"{state.get('delivering_therapy')}; service available="
                    f"{state.get('service_available')}"
                ),
                "assertion_class": "observed_fact",
                "confidence": 1.0,
            }
        ]
        if verification:
            findings.append(
                {
                    "statement": (
                        f"Recovery verification: {verification.get('outcome')} with "
                        f"{verification.get('checks_passed')}/"
                        f"{verification.get('checks_total')} checks passed; "
                        f"residual risk {verification.get('residual_risk', 0.0):.2f}"
                    ),
                    "assertion_class": "observed_fact",
                    "confidence": 1.0,
                }
            )
            for check in verification.get("checks", []):
                if not check.get("passed"):
                    findings.append(
                        {
                            "statement": (
                                f"Check failed: {check.get('name')} - observed "
                                f"{check.get('observed')}, expected "
                                f"{check.get('expected')}"
                            ),
                            "assertion_class": "observed_fact",
                            "confidence": 1.0,
                        }
                    )
        return {
            "findings": findings,
            "outcome": verification.get("outcome", "failed"),
            "residual_risk": verification.get("residual_risk", 1.0),
            "requires_reinvestigation": bool(verification.get("requires_reinvestigation", True)),
            "residual_cyber_risk": cyber.get("score"),
            "failed_checks": [
                c.get("name") for c in verification.get("checks", []) if not c.get("passed")
            ],
        }


# ===========================================================================
# Real providers
# ===========================================================================
class AnthropicProvider(LLMProvider):
    """Anthropic Messages API with structured tool calling.

    Requires ANTHROPIC_API_KEY. Not used by default, and never by the
    reproducible experiment suite; results obtained with it are reported
    separately with model version and across-run variance.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-sonnet-4-5",
        temperature: float = 0.0,
        max_tokens: int = 4096,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self._api_key:
            raise RuntimeError(
                "AnthropicProvider requires ANTHROPIC_API_KEY. Use "
                "AGENT_LLM_PROVIDER=deterministic to run offline."
            )
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the anthropic package is not installed; install it or use the "
                "deterministic provider"
            ) from exc
        self._client = anthropic.Anthropic(api_key=self._api_key)

    def respond(self, turn: ProviderTurn) -> ProviderResponse:  # pragma: no cover
        messages: list[dict[str, Any]] = [{"role": "user", "content": turn.task_prompt}]
        for tool_name, args, result in turn.observations:
            messages.append(
                {
                    "role": "assistant",
                    "content": f"Calling {tool_name} with {json.dumps(args)}",
                }
            )
            messages.append(
                {
                    "role": "user",
                    "content": f"Result of {tool_name}: {json.dumps(result, default=str)[:6000]}",
                }
            )
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=turn.system_prompt,
            tools=turn.tool_schemas or None,
            messages=messages,
        )
        tool_calls: list[ToolCallRequest] = []
        text_parts: list[str] = []
        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(
                    ToolCallRequest(tool_name=block.name, arguments=dict(block.input))
                )
            elif block.type == "text":
                text_parts.append(block.text)
        text = "\n".join(text_parts)
        final: dict[str, Any] | None = None
        if not tool_calls:
            final = _extract_json(text) or {"findings": [], "raw": text}
        return ProviderResponse(
            tool_calls=tool_calls,
            final_output=final,
            raw_text=text,
            model=self.model,
            input_tokens=getattr(response.usage, "input_tokens", 0),
            output_tokens=getattr(response.usage, "output_tokens", 0),
        )


def _extract_json(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of model text."""
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = text.find("{", start + 1)
    return None


def build_provider(
    provider: str | None = None, seed: int = 20260101, model: str | None = None
) -> LLMProvider:
    """Construct the configured provider.

    Defaults to the deterministic provider, so the platform runs with no
    API key and every experiment is reproducible by default.
    """
    name = (provider or os.environ.get("AGENT_LLM_PROVIDER", "deterministic")).lower()
    if name in {"deterministic", "offline", "none"}:
        return DeterministicProvider(seed=seed)
    if name == "anthropic":
        return AnthropicProvider(
            model=model or os.environ.get("AGENT_LLM_MODEL", "claude-sonnet-4-5")
        )
    raise ValueError(f"unknown provider {name!r}. Supported: deterministic, anthropic")


__all__ = [
    "ROLE_PLAN",
    "AnthropicProvider",
    "DeterministicProvider",
    "LLMProvider",
    "ProviderResponse",
    "ProviderTurn",
    "ToolCallRequest",
    "build_provider",
]
