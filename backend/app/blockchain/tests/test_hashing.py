import hashlib

from app.blockchain.hashing import hash_payload
from app.schemas.risk import RiskScore


def test_hash_payload_of_a_bare_string_hashes_it_directly():
    assert hash_payload("evidence-ref-123") == hashlib.sha256(b"evidence-ref-123").hexdigest()


def test_hash_payload_of_a_dict_is_stable_regardless_of_key_order():
    first = hash_payload({"a": 1, "b": 2})
    second = hash_payload({"b": 2, "a": 1})
    assert first == second


def test_hash_payload_of_a_dict_differs_when_values_differ():
    assert hash_payload({"a": 1}) != hash_payload({"a": 2})


def test_hash_payload_of_a_pydantic_model_is_deterministic():
    risk_score = RiskScore(
        incident_id="INC-1",
        cyber_risk=0.8,
        clinical_risk=0.2,
        response_impact={"isolate_critical": "low"},
        explanation="test",
    )
    assert hash_payload(risk_score) == hash_payload(risk_score)


def test_hash_payload_of_a_pydantic_model_differs_from_a_different_model():
    base = RiskScore(
        incident_id="INC-1",
        cyber_risk=0.8,
        clinical_risk=0.2,
        response_impact={"isolate_critical": "low"},
        explanation="test",
    )
    other = base.model_copy(update={"cyber_risk": 0.1})
    assert hash_payload(base) != hash_payload(other)


def test_hash_payload_returns_a_64_char_hex_digest():
    digest = hash_payload({"x": "y"})
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
