"""Policy-as-code: the Policy Engine's routing rules as a reviewable, hashable YAML file.

No LLM anywhere in this module. A policy is an ordered list of rules; the first rule whose
conditions all hold decides (`requires_human_approval`, `policy_rule_id`, rationale).

Safety properties enforced when a policy is loaded (it is refused otherwise):
  * every input is covered by some rule (no silent default);
  * floor F1: patient_dependency + {shutdown, isolate_critical} always needs a human;
  * floor F2: response_impact high or critical always needs a human.
A policy can add rules or tighten routing, never go below the floor.

`policy_hash` is SHA-256 over the validated policy as canonical JSON (sorted keys, no
whitespace, UTF-8), so comments and formatting do not change it but any rule change does.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from app.policy_engine.rules import _IMPACT_ORDER
from app.schemas.enums import ImpactLevel, ResponseActionCategory
from app.schemas.patient import AcuityBand

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.default.yaml")

SAFETY_FLOOR = (
    "patient-dependent device + shutdown/isolate_critical always requires human approval",
    "response_impact high or critical always requires human approval",
)
_FLOOR_ACTIONS = frozenset({ResponseActionCategory.SHUTDOWN, ResponseActionCategory.ISOLATE_CRITICAL})


class PolicyError(ValueError):
    """The policy is invalid, incomplete, or below the safety floor."""


def _coerce(enum_cls: type[Enum], value: Any) -> Any:
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError:
        pass
    if isinstance(value, str):
        try:
            return enum_cls[value.strip().upper()]
        except KeyError:
            pass
    raise ValueError(f"{value!r} is not a valid {enum_cls.__name__}")


class Conditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patient_dependency: StrictBool | None = None
    action_in: list[ResponseActionCategory] | None = None
    acuity: AcuityBand | None = None
    impact_at_most: ImpactLevel | None = None
    impact_equals: ImpactLevel | None = None
    impact_at_least: ImpactLevel | None = None

    @field_validator("impact_at_most", "impact_equals", "impact_at_least", mode="before")
    @classmethod
    def _impact(cls, v: Any) -> Any:
        return None if v is None else _coerce(ImpactLevel, v)

    @field_validator("acuity", mode="before")
    @classmethod
    def _acuity(cls, v: Any) -> Any:
        return None if v is None else _coerce(AcuityBand, v)

    @field_validator("action_in", mode="before")
    @classmethod
    def _actions(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, list) or not v:
            raise ValueError("action_in must be a non-empty list")
        return [_coerce(ResponseActionCategory, x) for x in v]


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    when: Conditions = Field(default_factory=Conditions)
    requires_human_approval: StrictBool
    rationale: str = Field(min_length=1)


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    name: str = Field(min_length=1)
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> PolicyDocument:
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


def _matches(
    when: Conditions,
    impact: ImpactLevel,
    patient_dependency: bool,
    action: ResponseActionCategory,
    acuity: AcuityBand | None,
) -> bool:
    if when.patient_dependency is not None and when.patient_dependency != patient_dependency:
        return False
    if when.action_in is not None and action not in when.action_in:
        return False
    if when.acuity is not None and acuity != when.acuity:
        return False
    rank = _IMPACT_ORDER[impact]
    if when.impact_at_most is not None and rank > _IMPACT_ORDER[when.impact_at_most]:
        return False
    if when.impact_equals is not None and rank != _IMPACT_ORDER[when.impact_equals]:
        return False
    return not (when.impact_at_least is not None and rank < _IMPACT_ORDER[when.impact_at_least])


def _classify(
    rules: list[Rule],
    impact: ImpactLevel,
    patient_dependency: bool,
    action: ResponseActionCategory,
    acuity: AcuityBand | None,
) -> tuple[bool, str, str]:
    for rule in rules:
        if _matches(rule.when, impact, patient_dependency, action, acuity):
            rationale = rule.rationale.replace("{action}", action.value)
            rationale = rationale.replace("{impact}", impact.value)
            return rule.requires_human_approval, rule.id, rationale
    raise PolicyError(
        f"no rule matches impact={impact.value} patient_dependency={patient_dependency} "
        f"action={action.value} acuity={acuity.value if acuity else None}"
    )


def _verify_safety_floor(rules: list[Rule], source: str) -> None:
    grid = itertools.product(ImpactLevel, (True, False), (None, *AcuityBand), ResponseActionCategory)
    for impact, dep, acuity, action in grid:
        try:
            requires, rule_id, _ = _classify(rules, impact, dep, action, acuity)
        except PolicyError as exc:
            raise PolicyError(f"policy {source} is incomplete: {exc}") from exc
        if dep and action in _FLOOR_ACTIONS and not requires:
            raise PolicyError(
                f"policy {source} violates the safety floor: rule {rule_id!r} lets "
                f"{action.value} run autonomously on a patient-dependent device"
            )
        if _IMPACT_ORDER[impact] >= _IMPACT_ORDER[ImpactLevel.HIGH] and not requires:
            raise PolicyError(
                f"policy {source} violates the safety floor: rule {rule_id!r} lets a "
                f"response_impact={impact.value} action run autonomously"
            )


def _canonical_hash(doc: PolicyDocument) -> str:
    canonical = json.dumps(
        doc.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyTable:
    doc: PolicyDocument
    policy_hash: str
    source: str

    def classify(
        self,
        impact: ImpactLevel,
        patient_dependency: bool,
        action: ResponseActionCategory,
        acuity: AcuityBand | None = None,
    ) -> tuple[bool, str, str]:
        """Same contract as `rules.classify_routing`: (requires_human_approval, rule_id, rationale)."""
        return _classify(self.doc.rules, impact, patient_dependency, action, acuity)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.doc.name,
            "version": self.doc.version,
            "policy_hash": self.policy_hash,
            "source": self.source,
            "safety_floor": list(SAFETY_FLOOR),
            "rules": [
                {
                    "id": r.id,
                    "when": r.when.model_dump(mode="json", exclude_none=True),
                    "requires_human_approval": r.requires_human_approval,
                    "rationale": r.rationale,
                }
                for r in self.doc.rules
            ],
        }


def load_policy_text(text: str, source: str) -> PolicyTable:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {source} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy {source} must be a YAML mapping")
    try:
        doc = PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"policy {source} is invalid: {exc}") from exc
    _verify_safety_floor(doc.rules, source)
    return PolicyTable(doc=doc, policy_hash=_canonical_hash(doc), source=source)


def load_policy_file(path: Path) -> PolicyTable:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path.name}: {exc}") from exc
    return load_policy_text(text, f"file:{path.name}")


def load_default_policy() -> PolicyTable:
    return load_policy_text(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"), "bundled:policy.default.yaml")


_active: PolicyTable | None = None


def get_active_table() -> PolicyTable:
    """The process-wide policy: `POLICY_FILE` if set, else the bundled default. Loaded once.
    An invalid or sub-floor policy raises -- there is deliberately no fallback."""
    global _active
    if _active is None:
        path = os.environ.get("POLICY_FILE", "").strip()
        _active = load_policy_file(Path(path)) if path else load_default_policy()
    return _active


def reset_active_table() -> None:
    global _active
    _active = None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m app.policy_engine.table POLICY.yaml")
        return 2
    try:
        table = load_policy_file(Path(args[0]))
    except PolicyError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(table.policy_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
