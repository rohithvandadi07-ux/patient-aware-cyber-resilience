"""RiskModel protocol -- the fixed interface, per architecture spec Section 12.

"The interface is fixed now; the function behind it is not (Section 3, Risk 5
resolution)." `RuleBasedRiskModel` (this package's v0 implementation, in
`rule_based.py`) is one concrete `RiskModel`; any later learned/weighted model
is a second implementation behind the same interface, swappable as a config
change rather than an API rewrite.

**Schema note (read before changing anything here):** Section 12's prose says
`response_impact: dict[action_id, float]`, but the actual `RiskScore` Pydantic
schema (`app/schemas/risk.py`, built in Phase 1) types it
`dict[str, ImpactLevel]` -- a coarse four-level category, not a continuous
float -- and `ProposedResponse.clinical_impact` (Phase 1's agent schemas) uses
the same `dict[str, ImpactLevel]` shape. This module builds against the real,
already-shipped schema (`ImpactLevel`), not the prose's `float` claim,
because: (1) the schema is what Phase 4's Response Planning Agent already
produces and consumes, so diverging from it here would break that contract;
(2) `ImpactLevel`'s own docstring says it is deliberately "used for both
clinical impact and response impact -- same scale," which only works as a
four-level category, not a float. If a future phase wants continuous-valued
response impact, that is a schema change to make deliberately, with its own
migration, not something to quietly introduce in the risk engine alone.
"""

from typing import Protocol

from app.schemas.agents import CandidateAction, ClinicalContext, ThreatAssessment
from app.schemas.risk import RiskScore


class RiskModel(Protocol):
    def calculate_risk(
        self,
        threat: ThreatAssessment,
        context: ClinicalContext,
        candidate_responses: list[CandidateAction],
    ) -> RiskScore: ...
