import pytest
from pydantic import ValidationError

from app.schemas.agents import CandidateAction, ProposedResponse
from app.schemas.enums import ResponseActionCategory as A


def _proposal(recommended):
    return ProposedResponse(
        incident_id="inc-1",
        candidate_actions=[
            CandidateAction(action_category=A.BLOCK_TRAFFIC, description="block"),
            CandidateAction(action_category=A.ROTATE_CREDENTIALS, description="rotate"),
        ],
        security_benefit={},
        clinical_impact={},
        recommended_action=recommended,
        rationale="r",
    )


def test_recommendation_must_be_one_of_the_candidates():
    assert _proposal(A.BLOCK_TRAFFIC).recommended_action == A.BLOCK_TRAFFIC


def test_recommendation_outside_the_candidates_is_rejected():
    with pytest.raises(ValidationError, match="not one of the candidate_actions"):
        _proposal(A.ISOLATE_NON_CRITICAL)
