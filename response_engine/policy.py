"""Deterministic controlled-autonomy policy engine.

Receives a candidate action plus the authoritative risk results and returns
exactly one verdict: ``AUTO_ALLOWED``, ``APPROVAL_REQUIRED`` or ``DENIED``.

Design properties that matter:

* **Deterministic and total.** Every input produces a verdict; the rule set
  ends with a catch-all whose decision is ``APPROVAL_REQUIRED``. A policy
  whose fall-through is permissive is not a safety policy.
* **First match wins, denials first.** The matched rule's name is recorded,
  so every autonomous action is attributable to a specific published rule
  rather than to an opaque score.
* **Denial is not escalation.** An action classified unsafe is denied, not
  forwarded for approval. Asking a human to authorise something the system
  has judged unsafe converts a safety judgement into a liability transfer,
  and a clinician under time pressure is the wrong place to relocate it.
* **No LLM participates.** The agentic layer cannot reach this module's
  decision; it can only ask what the verdict *would* be
  (``evaluate_policy``), which authorises nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from backend.app.domain.enums import (
    AssertionClass,
    CriticalityTier,
    ImpactClass,
    PolicyDecision,
    ResponseActionType,
)
from backend.app.domain.models import (
    ClinicalRiskResult,
    CyberRiskResult,
    DeviceProfile,
    DeviceState,
    PolicyEvaluation,
    ResponseImpactResult,
)
from risk_engine.impact import THERAPY_INTERRUPTING

DEFAULT_POLICY_PATH = Path("configs/policy.default.yaml")

#: Ordering of impact classes for ``min_impact_class`` comparisons.
IMPACT_ORDER: tuple[ImpactClass, ...] = (
    ImpactClass.LOW,
    ImpactClass.MODERATE,
    ImpactClass.HIGH,
    ImpactClass.UNSAFE,
)

#: Condition keys a rule may use. Deliberately small so the rule language
#: stays auditable; an unknown key is a load-time error rather than a
#: silently ignored condition.
KNOWN_CONDITIONS: frozenset[str] = frozenset(
    {
        "impact_class",
        "min_impact_class",
        "min_clinical_risk",
        "max_clinical_risk",
        "min_cyber_risk",
        "max_cyber_risk",
        "min_cyber_uncertainty",
        "min_clinical_uncertainty",
        "life_support_involved",
        "interrupts_life_sustaining_therapy",
        "safe_alternative_available",
        "already_attempted",
        "reversible",
        "allowed_criticality",
        "action_in",
    }
)


def impact_rank(impact: ImpactClass) -> int:
    return IMPACT_ORDER.index(impact)


class PolicyValidationError(ValueError):
    """Raised when a policy profile is structurally invalid."""


@dataclass(frozen=True)
class PolicyRule:
    name: str
    decision: PolicyDecision
    conditions: dict[str, Any]
    reason: str = ""
    required_role: str | None = None


@dataclass
class PolicyContext:
    """Everything a policy decision may consider.

    Assembled by the response orchestrator from authoritative sources. A
    rule cannot reach anything outside this object, which is what keeps the
    rule language small enough to audit.
    """

    action: ResponseActionType
    impact: ResponseImpactResult
    cyber_risk: CyberRiskResult
    clinical_risk: ClinicalRiskResult
    device: DeviceProfile | None = None
    state: DeviceState | None = None
    already_attempted: bool = False
    autonomous_actions_taken: int = 0

    # -- derived predicates ------------------------------------------------
    @property
    def interrupts_life_sustaining_therapy(self) -> bool:
        if self.action not in THERAPY_INTERRUPTING:
            return False
        if not self.clinical_risk.life_support_involved:
            return False
        return bool(self.state.delivering_therapy) if self.state else True

    @property
    def safe_alternative_available(self) -> bool:
        return bool(
            self.device and self.device.has_redundant_peer and self.device.supports_safe_failover
        )

    @property
    def criticality(self) -> CriticalityTier | None:
        return self.device.criticality if self.device else None


class PolicyEngine:
    """Evaluates the declared rule set against a :class:`PolicyContext`."""

    def __init__(
        self,
        rules: list[PolicyRule],
        policy_version: str = "v1",
        approval: dict[str, Any] | None = None,
        autonomy: dict[str, Any] | None = None,
        source_path: str | None = None,
    ) -> None:
        if not rules:
            raise PolicyValidationError("policy has no rules")
        self.rules = rules
        self.policy_version = policy_version
        self.approval = approval or {}
        self.autonomy = autonomy or {"enabled": True}
        self.source_path = source_path
        self._validate()

    # -- loading -----------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path | None = None) -> PolicyEngine:
        p = Path(path) if path else DEFAULT_POLICY_PATH
        if not p.exists():
            raise FileNotFoundError(
                f"policy profile not found at {p}. The engine refuses to run "
                "with built-in defaults: an unpublished policy cannot be "
                "audited or reproduced."
            )
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        return cls.from_dict(data, source_path=str(p))

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str | None = None) -> PolicyEngine:
        raw_rules = data.get("rules")
        if not raw_rules:
            raise PolicyValidationError("policy has no rules")
        rules: list[PolicyRule] = []
        for entry in raw_rules:
            try:
                decision = PolicyDecision(entry["decision"])
            except (KeyError, ValueError) as exc:
                raise PolicyValidationError(
                    f"rule {entry.get('name')!r} has an invalid decision: {exc}"
                ) from exc
            rules.append(
                PolicyRule(
                    name=str(entry["name"]),
                    decision=decision,
                    conditions=dict(entry.get("when") or {}),
                    reason=" ".join(str(entry.get("reason", "")).split()),
                    required_role=entry.get("required_role"),
                )
            )
        return cls(
            rules=rules,
            policy_version=str(data.get("policy_version", "v1")),
            approval=data.get("approval") or {},
            autonomy=data.get("autonomy") or {"enabled": True},
            source_path=source_path,
        )

    def _validate(self) -> None:
        names = [r.name for r in self.rules]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise PolicyValidationError(f"duplicate rule names: {sorted(duplicates)}")

        for rule in self.rules:
            unknown = sorted(set(rule.conditions) - KNOWN_CONDITIONS)
            if unknown:
                raise PolicyValidationError(
                    f"rule {rule.name!r} uses unknown conditions {unknown}. "
                    f"Supported: {sorted(KNOWN_CONDITIONS)}"
                )

        # The rule set must be TOTAL: a final catch-all with no conditions.
        if self.rules[-1].conditions:
            raise PolicyValidationError(
                "the last rule must be an unconditional catch-all so the "
                "policy is total; otherwise some input produces no verdict"
            )
        if self.rules[-1].decision is PolicyDecision.AUTO_ALLOWED:
            raise PolicyValidationError(
                "the catch-all rule must not auto-allow. A policy whose "
                "fall-through is permissive is not a safety policy."
            )

        # Unsafe impact must be denied before any rule can permit action,
        # or the central safety property does not hold.
        first_permissive = next(
            (i for i, r in enumerate(self.rules) if r.decision is PolicyDecision.AUTO_ALLOWED),
            None,
        )
        if first_permissive is not None:
            denies_unsafe = any(
                r.decision is PolicyDecision.DENIED
                and ImpactClass.UNSAFE.value
                in {str(v) for v in r.conditions.get("impact_class", [])}
                for r in self.rules[:first_permissive]
            )
            if not denies_unsafe:
                raise PolicyValidationError(
                    "no rule denies impact_class=unsafe before the first "
                    "auto-allow rule; an unsafe action could be permitted"
                )

    # -- evaluation --------------------------------------------------------
    def evaluate(self, ctx: PolicyContext) -> PolicyEvaluation:
        """Return the verdict for one candidate action."""
        # Master switch, used by the 'without controlled autonomy' ablation.
        if not self.autonomy.get("enabled", True):
            return PolicyEvaluation(
                action_type=ctx.action,
                decision=PolicyDecision.APPROVAL_REQUIRED,
                impact_class=ctx.impact.impact_class,
                matched_rule="autonomy_disabled",
                reasons=[
                    "autonomy is disabled in this configuration; every action "
                    "requires human approval"
                ],
                required_role="clinical_approver",
                policy_version=self.policy_version,
            )

        for rule in self.rules:
            if not self._matches(rule, ctx):
                continue

            reasons = [rule.reason] if rule.reason else []
            reasons.extend(self._evidence(ctx))

            # Budget guard: an auto-allowed action still escalates once the
            # per-incident autonomous budget is spent, so a loop that is not
            # converging cannot keep acting without a human seeing it.
            budget = int(self.autonomy.get("max_autonomous_actions_per_incident", 3))
            if (
                rule.decision is PolicyDecision.AUTO_ALLOWED
                and ctx.autonomous_actions_taken >= budget
            ):
                return PolicyEvaluation(
                    action_type=ctx.action,
                    decision=PolicyDecision.APPROVAL_REQUIRED,
                    impact_class=ctx.impact.impact_class,
                    matched_rule=f"{rule.name}+autonomy_budget_exhausted",
                    reasons=[
                        *reasons,
                        f"{ctx.autonomous_actions_taken} autonomous actions "
                        f"already taken for this incident (budget {budget}); "
                        "escalating so a human sees a loop that is not "
                        "converging",
                    ],
                    required_role="soc_analyst",
                    policy_version=self.policy_version,
                )

            return PolicyEvaluation(
                action_type=ctx.action,
                decision=rule.decision,
                impact_class=ctx.impact.impact_class,
                matched_rule=rule.name,
                reasons=reasons,
                required_role=rule.required_role,
                policy_version=self.policy_version,
                assertion_class=AssertionClass.OBSERVED_FACT,
            )

        raise AssertionError(  # pragma: no cover - _validate guarantees a catch-all
            "policy produced no verdict despite validation"
        )

    def _matches(self, rule: PolicyRule, ctx: PolicyContext) -> bool:
        c = rule.conditions
        if not c:
            return True

        if "impact_class" in c and ctx.impact.impact_class.value not in {
            str(v) for v in c["impact_class"]
        }:
            return False
        if "min_impact_class" in c:
            floor = ImpactClass(str(c["min_impact_class"]))
            if impact_rank(ctx.impact.impact_class) < impact_rank(floor):
                return False
        if "min_clinical_risk" in c and ctx.clinical_risk.score < float(c["min_clinical_risk"]):
            return False
        if "max_clinical_risk" in c and ctx.clinical_risk.score > float(c["max_clinical_risk"]):
            return False
        if "min_cyber_risk" in c and ctx.cyber_risk.score < float(c["min_cyber_risk"]):
            return False
        if "max_cyber_risk" in c and ctx.cyber_risk.score > float(c["max_cyber_risk"]):
            return False
        if "min_cyber_uncertainty" in c and ctx.cyber_risk.uncertainty < float(
            c["min_cyber_uncertainty"]
        ):
            return False
        if "min_clinical_uncertainty" in c and ctx.clinical_risk.uncertainty < float(
            c["min_clinical_uncertainty"]
        ):
            return False
        if "life_support_involved" in c and bool(
            ctx.clinical_risk.life_support_involved
        ) is not bool(c["life_support_involved"]):
            return False
        if "interrupts_life_sustaining_therapy" in c and (
            ctx.interrupts_life_sustaining_therapy
            is not bool(c["interrupts_life_sustaining_therapy"])
        ):
            return False
        if "safe_alternative_available" in c and (
            ctx.safe_alternative_available is not bool(c["safe_alternative_available"])
        ):
            return False
        if "already_attempted" in c and ctx.already_attempted is not bool(c["already_attempted"]):
            return False
        if "reversible" in c and ctx.impact.reversible is not bool(c["reversible"]):
            return False
        if "allowed_criticality" in c:
            allowed = {str(v) for v in c["allowed_criticality"]}
            if ctx.criticality is None or ctx.criticality.value not in allowed:
                return False
        return not (
            "action_in" in c
            and ctx.action.value not in {str(v) for v in c["action_in"]}
        )

    @staticmethod
    def _evidence(ctx: PolicyContext) -> list[str]:
        """Concrete values that made a rule match, for the audit trail."""
        out = [
            f"action={ctx.action.value}",
            f"impact_class={ctx.impact.impact_class.value}",
            f"clinical_impact={ctx.impact.clinical_impact:.2f}",
            f"cyber_risk={ctx.cyber_risk.score:.2f} (uncertainty {ctx.cyber_risk.uncertainty:.2f})",
            f"clinical_risk={ctx.clinical_risk.score:.2f}"
            f" (uncertainty {ctx.clinical_risk.uncertainty:.2f})",
        ]
        if ctx.criticality:
            out.append(f"device_criticality={ctx.criticality.value}")
        if ctx.clinical_risk.life_support_involved:
            out.append("life_support_involved=true")
        if ctx.safe_alternative_available:
            out.append("safe_alternative_available=true")
        if ctx.already_attempted:
            out.append("already_attempted=true")
        if not ctx.impact.reversible:
            out.append("reversible=false")
        return out

    # -- helpers -----------------------------------------------------------
    @property
    def approval_timeout_seconds(self) -> float:
        return float(self.approval.get("timeout_seconds", 900))

    @property
    def deny_on_timeout(self) -> bool:
        return str(self.approval.get("on_timeout", "deny")).lower() == "deny"

    @property
    def min_justification_chars(self) -> int:
        return int(self.approval.get("min_justification_chars", 20))

    def fingerprint(self) -> str:
        """Hash of the whole policy, recorded in every provenance entry."""
        from backend.app.domain.ids import canonical_hash

        return canonical_hash(
            {
                "policy_version": self.policy_version,
                "rules": [
                    {
                        "name": r.name,
                        "decision": r.decision.value,
                        "when": r.conditions,
                        "required_role": r.required_role,
                    }
                    for r in self.rules
                ],
                "approval": self.approval,
                "autonomy": self.autonomy,
            }
        )[:16]

    def with_autonomy_disabled(self) -> PolicyEngine:
        """For the 'without controlled autonomy' ablation."""
        return PolicyEngine(
            rules=self.rules,
            policy_version=self.policy_version,
            approval=self.approval,
            autonomy={**self.autonomy, "enabled": False},
            source_path=f"{self.source_path}+autonomy_disabled",
        )


def load_default_policy() -> PolicyEngine:
    return PolicyEngine.load()


__all__ = [
    "DEFAULT_POLICY_PATH",
    "IMPACT_ORDER",
    "KNOWN_CONDITIONS",
    "PolicyContext",
    "PolicyEngine",
    "PolicyRule",
    "PolicyValidationError",
    "impact_rank",
    "load_default_policy",
]
