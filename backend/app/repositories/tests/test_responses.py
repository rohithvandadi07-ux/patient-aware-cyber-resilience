import pytest

from app.repositories.responses import (
    ExecutedResponseRepository,
    ProposedResponseNotFoundError,
    ProposedResponseRepository,
)
from app.schemas.enums import ResponseActionCategory
from app.schemas.policy import PolicyDecision
from app.schemas.response import ExecutedResponse

TS = "2026-10-12T00:00:00+00:00"


def _decision(incident_id="INC-1", chosen_action=ResponseActionCategory.ISOLATE_CRITICAL):
    return PolicyDecision(
        incident_id=incident_id,
        chosen_action=chosen_action,
        requires_human_approval=False,
        policy_rule_id="RULE-1",
        rationale="test rationale",
    )


def _executed(incident_id="INC-1"):
    return ExecutedResponse(
        incident_id=incident_id,
        action_taken=ResponseActionCategory.ISOLATE_CRITICAL,
        executed_by="system",
        timestamp=TS,
        chain_tx_id=None,
    )


def test_put_and_get_round_trip():
    repo = ProposedResponseRepository()
    decision = _decision()
    repo.put(decision)
    assert repo.get("INC-1") == decision


def test_put_replaces_prior_decision_for_same_incident():
    repo = ProposedResponseRepository()
    repo.put(_decision(chosen_action=ResponseActionCategory.BLOCK_TRAFFIC))
    repo.put(_decision(chosen_action=ResponseActionCategory.ISOLATE_CRITICAL))
    assert repo.get("INC-1").chosen_action == ResponseActionCategory.ISOLATE_CRITICAL
    assert len(repo.list_all()) == 1


def test_get_unknown_incident_raises():
    repo = ProposedResponseRepository()
    with pytest.raises(ProposedResponseNotFoundError):
        repo.get("does-not-exist")


def test_remove_is_a_no_op_for_an_absent_incident():
    repo = ProposedResponseRepository()
    repo.remove("does-not-exist")  # must not raise
    assert repo.list_all() == []


def test_remove_clears_a_pending_decision():
    repo = ProposedResponseRepository()
    repo.put(_decision())
    repo.remove("INC-1")
    with pytest.raises(ProposedResponseNotFoundError):
        repo.get("INC-1")


def test_executed_response_repository_is_append_only_per_incident():
    repo = ExecutedResponseRepository()
    repo.record(_executed("INC-1"))
    repo.record(_executed("INC-2"))
    repo.record(_executed("INC-1"))

    assert len(repo.list_all()) == 3
    assert len(repo.list_for_incident("INC-1")) == 2
    assert len(repo.list_for_incident("INC-2")) == 1
