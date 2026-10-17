"""Exhaustive check of the real Risk Engine + Policy Engine over their whole input space.

The patient-safety comparison samples trials from a dataset, so it can only say "no
unsafe action occurred in N trials". The decision layer is small enough to do better
for the part that matters: enumerate EVERY combination of

    response action (all categories) x device criticality (3) x patient dependency (2)
    x stated clinical impact (all levels) x threat severity (all levels)
    x threat confidence {0.1, 0.5, 0.9}

call the real `RuleBasedRiskModel.calculate_risk` and `PolicyEngine.evaluate_action`
on each, and count outcomes. The result is a statement about all inputs, not a
sample. Properties checked:

P-A  for a patient-dependent device, no severe action (shutdown, isolate-critical,
     quarantine segment, failover) is ever allowed autonomously;
P-B  for a HIGH-criticality, patient-dependent device, no action of any tier is ever
     allowed autonomously;
P-C  the decision does not depend on the threat confidence or on the stated
     severity (these two only enter the cyber-risk score, not the routing).

Usage (from `backend/`):  python -m app.evaluation.run_policy_exhaustive --out out.json
"""

from __future__ import annotations

import argparse
import itertools
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    ResponseActionCategory,
)

SEVERE = {"shutdown", "isolate_critical", "quarantine_segment", "failover"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    risk = RuleBasedRiskModel()
    policy = PolicyEngine()
    actions = list(ResponseActionCategory)
    total = 0
    autonomous = 0
    by_action: dict[str, Counter] = defaultdict(Counter)
    by_context: dict[str, Counter] = defaultdict(Counter)
    viol_a = viol_b = 0
    decision_by_core: dict[tuple, set] = defaultdict(set)

    for action, crit, dep, impact, sev, conf in itertools.product(
        actions, list(DeviceCriticality), (False, True), list(ImpactLevel), list(ImpactLevel), (0.1, 0.5, 0.9)
    ):
        threat = ThreatAssessment(
            incident_id="X", attack_type=AttackCategory.UNKNOWN, severity=sev, confidence=conf,
            propagation_risk=sev, reasoning_summary="exhaustive",
        )
        ctx = ClinicalContext(
            incident_id="X", device_criticality=crit, patient_dependency=dep, clinical_impact_level=impact
        )
        score = risk.calculate_risk(threat, ctx, [CandidateAction(action_category=action, description="x")])
        decision = policy.evaluate_action(score, ctx, action)
        human = bool(decision.requires_human_approval)
        total += 1
        autonomous += 0 if human else 1
        by_action[action.value]["human" if human else "auto"] += 1
        key = f"{crit.value}|{'dependent' if dep else 'independent'}"
        by_context[key]["human" if human else "auto"] += 1
        if dep and action.value in SEVERE and not human:
            viol_a += 1
        if crit == DeviceCriticality.HIGH and dep and not human:
            viol_b += 1
        decision_by_core[(action.value, crit.value, dep, impact.value)].add(human)

    p_c_ok = all(len(v) == 1 for v in decision_by_core.values())
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "combinations": total,
        "autonomous": autonomous,
        "human": total - autonomous,
        "actions": [a.value for a in actions],
        "by_action": {k: dict(v) for k, v in by_action.items()},
        "by_context": {k: dict(v) for k, v in by_context.items()},
        "violations_P_A_severe_on_patient_dependent": viol_a,
        "violations_P_B_any_action_on_high_dependent": viol_b,
        "P_C_decision_independent_of_severity_and_confidence": p_c_ok,
    }
    args.out.write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
