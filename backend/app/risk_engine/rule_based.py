"""RuleBasedRiskModel -- v0 RiskModel implementation (architecture spec
Section 12).

Assembles the named rule functions in `rules.py` into one `RiskModel`-shaped
object. Deliberately thin: this module contains no scoring logic of its own,
only wiring -- every actual rule and its rationale lives in `rules.py`, where
each is independently named and testable, per Section 12's "explicit,
documented table, not a trained model."
"""

from app.risk_engine.rules import score_clinical_risk, score_cyber_risk, score_response_impact
from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.risk import RiskScore


class RuleBasedRiskModel:
    """v0 `RiskModel`: explicit rule tables, no learned component anywhere.

    Conforms to the `RiskModel` Protocol in `model.py` structurally (Python
    Protocols don't require inheritance) -- `calculate_risk` matches that
    Protocol's signature exactly.
    """

    def calculate_risk(
        self,
        threat: ThreatAssessment,
        context: ClinicalContext,
        candidate_responses: list[CandidateAction],
    ) -> RiskScore:
        if not candidate_responses:
            raise ValueError(
                "candidate_responses must be non-empty -- RiskScore.response_impact needs at "
                "least one candidate action to score (Section 12: 'one entry per candidate "
                "action under consideration')"
            )
        if threat.incident_id != context.incident_id:
            raise ValueError(
                f"threat.incident_id ({threat.incident_id!r}) and context.incident_id "
                f"({context.incident_id!r}) must match -- refusing to assemble a RiskScore "
                "that mixes evidence from two different incidents"
            )

        cyber_risk, cyber_explanation = score_cyber_risk(threat)
        clinical_risk, clinical_explanation = score_clinical_risk(context)

        response_impact = {}
        action_explanations = []
        for action in candidate_responses:
            impact, action_explanation = score_response_impact(action.action_category, context)
            response_impact[action.action_category.value] = impact
            action_explanations.append(action_explanation)

        explanation = "; ".join([cyber_explanation, clinical_explanation, *action_explanations])

        return RiskScore(
            incident_id=threat.incident_id,
            cyber_risk=cyber_risk,
            clinical_risk=clinical_risk,
            response_impact=response_impact,
            explanation=explanation,
        )
