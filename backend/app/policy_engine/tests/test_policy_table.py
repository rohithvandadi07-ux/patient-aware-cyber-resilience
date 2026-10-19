import itertools
from pathlib import Path

import pytest
import yaml

from app.policy_engine.rules import classify_routing
from app.policy_engine.table import (
    DEFAULT_POLICY_PATH,
    PolicyError,
    get_active_table,
    load_default_policy,
    load_policy_text,
    reset_active_table,
)
from app.schemas.enums import ImpactLevel, ResponseActionCategory
from app.schemas.patient import AcuityBand

GRID = list(itertools.product(ImpactLevel, (True, False), (None, *AcuityBand), ResponseActionCategory))


@pytest.fixture(autouse=True)
def _fresh_active_table():
    reset_active_table()
    yield
    reset_active_table()


def _doc() -> dict:
    return yaml.safe_load(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))


def _text(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False)


def _rule(doc: dict, rule_id: str) -> dict:
    return next(r for r in doc["rules"] if r["id"] == rule_id)


def test_default_policy_matches_python_rules_exactly():
    table = load_default_policy()
    for impact, dep, acuity, action in GRID:
        got = table.classify(impact, dep, action, acuity)
        want = classify_routing(impact, dep, action, acuity)
        assert got == want, (impact, dep, acuity, action)


def test_policy_cannot_drop_patient_dependent_severe_rule():
    doc = _doc()
    doc["rules"] = [r for r in doc["rules"] if r["id"] != "patient_dependent_severe_action"]
    with pytest.raises(PolicyError, match="safety floor"):
        load_policy_text(_text(doc), "t")


def test_policy_cannot_let_high_impact_run_autonomously():
    doc = _doc()
    _rule(doc, "approval_high_impact")["requires_human_approval"] = False
    with pytest.raises(PolicyError, match="safety floor"):
        load_policy_text(_text(doc), "t")


def test_policy_must_cover_every_input():
    doc = _doc()
    doc["rules"] = [r for r in doc["rules"] if r["id"] != "approval_high_impact"]
    with pytest.raises(PolicyError, match="no rule matches"):
        load_policy_text(_text(doc), "t")


def test_unknown_condition_key_is_refused():
    doc = _doc()
    _rule(doc, "autonomous_low_impact")["when"]["typo_key"] = True
    with pytest.raises(PolicyError):
        load_policy_text(_text(doc), "t")


def test_unknown_action_is_refused():
    doc = _doc()
    _rule(doc, "patient_dependent_severe_action")["when"]["action_in"] = ["nuke_it"]
    with pytest.raises(PolicyError):
        load_policy_text(_text(doc), "t")


def test_duplicate_rule_ids_are_refused():
    doc = _doc()
    doc["rules"].append(dict(doc["rules"][0]))
    with pytest.raises(PolicyError):
        load_policy_text(_text(doc), "t")


def test_invalid_yaml_is_refused():
    with pytest.raises(PolicyError):
        load_policy_text("rules: [unclosed", "t")
    with pytest.raises(PolicyError):
        load_policy_text("- just\n- a list\n", "t")


def test_hash_is_stable_and_ignores_comments():
    base = DEFAULT_POLICY_PATH.read_text(encoding="utf-8")
    a = load_policy_text(base, "t").policy_hash
    b = load_policy_text("# reviewer note\n" + base, "t").policy_hash
    assert a == b
    assert len(a) == 64


def test_hash_changes_when_a_rule_changes():
    doc = _doc()
    _rule(doc, "autonomous_low_impact")["rationale"] += " (changed)"
    assert load_policy_text(_text(doc), "t").policy_hash != load_default_policy().policy_hash


def test_policy_file_env_override_is_loaded(tmp_path: Path, monkeypatch):
    doc = _doc()
    _rule(doc, "autonomous_low_impact")["rationale"] += " (site policy v2)"
    path = tmp_path / "site.yaml"
    path.write_text(_text(doc), encoding="utf-8")
    monkeypatch.setenv("POLICY_FILE", str(path))
    reset_active_table()
    active = get_active_table()
    assert active.source == "file:site.yaml"
    assert active.policy_hash != load_default_policy().policy_hash


def test_invalid_policy_file_fails_closed(tmp_path: Path, monkeypatch):
    doc = _doc()
    _rule(doc, "approval_high_impact")["requires_human_approval"] = False
    path = tmp_path / "bad.yaml"
    path.write_text(_text(doc), encoding="utf-8")
    monkeypatch.setenv("POLICY_FILE", str(path))
    reset_active_table()
    with pytest.raises(PolicyError):
        get_active_table()
