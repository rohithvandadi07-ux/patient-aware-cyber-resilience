"""Patient-aware dual-risk engine.

Deterministic and authoritative. The agentic layer proposes; this engine
scores and selects; the policy engine then decides what is permitted.
"""

from risk_engine.clinical import ClinicalRiskScorer
from risk_engine.cyber import CyberRiskScorer
from risk_engine.engine import PatientAwareRiskEngine, ScoredCandidate
from risk_engine.impact import (
    CONNECTIVITY_AFFECTING,
    THERAPY_INTERRUPTING,
    ResponseImpactScorer,
)
from risk_engine.profile import (
    ProfileValidationError,
    RiskProfile,
    load_default_profile,
)

__all__ = [
    "CONNECTIVITY_AFFECTING",
    "THERAPY_INTERRUPTING",
    "ClinicalRiskScorer",
    "CyberRiskScorer",
    "PatientAwareRiskEngine",
    "ProfileValidationError",
    "ResponseImpactScorer",
    "RiskProfile",
    "ScoredCandidate",
    "load_default_profile",
]
