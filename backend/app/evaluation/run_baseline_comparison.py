"""Phase 13 -- runs the detection-only / fixed-response / full-system
comparison and writes a real, reported-numbers report to `evaluation/`.

Architecture spec Section 19's Phase 13 gate: "At least the detection-only
vs. full-system baseline comparison has real, reported numbers." Section 18:
patient-safety metrics "become real once Phase 5-6 exist and Scenario
B-style tests can be run at scale across many randomized scenario
parameters, not just the two fixed scenarios in Section 17." This script is
that at-scale run.

Data source, stated plainly because it matters: this trains fresh,
in-process, against `synthetic_data.py`'s synthetic stand-in dataset -- the
same one Phase 3's own training pipeline uses, and for the same reason (no
network access in this project's development environment to download the
real CICIoMT2024 dataset; see `datasets/LICENSE_NOTES.md`). It does not load
a pre-existing committed model artifact (none is committed -- trained
artifacts are gitignored per Section 8, and this project's established
pattern, used identically by `backend/tests/test_lifecycle_integration.py`
and `tests/e2e/conftest.py`, is to train a real model fresh for whatever
needs one rather than depend on one already existing on disk). Every number
this script reports is really computed by this run, not a placeholder --
see `app/evaluation/baseline_systems.py`'s module docstring for exactly what
is real (the detector, the Risk Engine, the Policy Engine) and what is a
disclosed, deterministic stand-in (the three agents nothing in this codebase
has a real LLM backend for yet).

Usage: `cd backend && python -m app.evaluation.run_baseline_comparison`
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import train_baselines
from app.evaluation.baseline_systems import (
    DetectionOutcome,
    SystemDecision,
    SystemName,
    decide_detection_only,
    decide_fixed_response,
    decide_full_system,
    detection_outcome_from_row,
    is_high_stakes,
    is_unnecessary_isolation,
    is_unsafe_autonomous_action,
    sample_device_contexts,
)
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel

# Repo root is 3 levels above this file (app/evaluation/run_baseline_comparison.py
# -> app/evaluation -> app -> backend -> repo root), resolved explicitly rather
# than via a bare relative path, so this script writes to the same
# `evaluation/` directory regardless of whether it is invoked from `backend/`
# or the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_OUTPUT_DIR = _REPO_ROOT / "evaluation"

_TRAINING_SEED = 42  # same default as app/cybersecurity/training.py
_DEVICE_CONTEXT_SEED = 2026  # independent seed -- device context must not
# be correlated with which row of the dataset it is paired with (see
# baseline_systems.sample_device_contexts's own docstring).

_SYSTEM_DECIDERS = {
    SystemName.DETECTION_ONLY: lambda detection, context, incident_id, risk_model, policy_engine: (
        decide_detection_only(detection, context)
    ),
    SystemName.FIXED_RESPONSE: lambda detection, context, incident_id, risk_model, policy_engine: (
        decide_fixed_response(detection, context)
    ),
    SystemName.FULL_SYSTEM: lambda detection, context, incident_id, risk_model, policy_engine: (
        decide_full_system(
            detection, context, incident_id, risk_model=risk_model, policy_engine=policy_engine
        )
    ),
}


def _rate(numerator: int, denominator: int) -> float | None:
    """`None` (never a fabricated 0.0 or NaN) when the denominator is zero --
    an honest "not enough trials sampled this population" rather than a
    number that looks measured but isn't."""
    return (numerator / denominator) if denominator > 0 else None


def run_comparison_for_model(
    model_name: str,
    X_test,
    y_test,
    predictions,
    confidences,
    *,
    device_context_seed: int,
) -> dict[str, Any]:
    """Runs all three systems over every row of one model's held-out test
    split, paired with independently-sampled device contexts, and returns
    the aggregated real numbers for that model."""
    n = len(X_test)
    contexts = sample_device_contexts(n, seed=device_context_seed)
    risk_model = RuleBasedRiskModel()
    policy_engine = PolicyEngine()

    decisions: dict[SystemName, list[SystemDecision]] = {name: [] for name in SystemName}
    detections: list[DetectionOutcome] = []

    for i in range(n):
        detection = detection_outcome_from_row(
            ground_truth_label=str(y_test.iloc[i]),
            predicted_label=str(predictions.iloc[i]),
            confidence=float(confidences[i]),
        )
        detections.append(detection)
        context = contexts[i]
        incident_id = f"EVAL-{model_name}-{i}"

        for system_name, decider in _SYSTEM_DECIDERS.items():
            decisions[system_name].append(
                decider(detection, context, incident_id, risk_model, policy_engine)
            )

    total = n
    total_fired = sum(1 for d in detections if d.fired)
    total_real_attacks = sum(1 for d in detections if d.ground_truth_is_attack)
    total_false_positives = sum(1 for d in detections if d.is_false_positive)
    total_high_stakes_real_attacks = sum(
        1 for d, c in zip(detections, contexts, strict=True) if d.ground_truth_is_attack and is_high_stakes(c)
    )

    per_system: dict[str, Any] = {}
    for system_name, system_decisions in decisions.items():
        unsafe_numerator = sum(1 for d in system_decisions if is_unsafe_autonomous_action(d))
        unnecessary_numerator = sum(1 for d in system_decisions if is_unnecessary_isolation(d))
        autonomous_executions = sum(1 for d in system_decisions if d.executed_action is not None)
        approvals_required = sum(1 for d in system_decisions if d.requires_human_approval is True)

        per_system[system_name.value] = {
            "autonomous_executions": autonomous_executions,
            "awaiting_human_approval": approvals_required,
            "unsafe_autonomous_action_rate": {
                "rate": _rate(unsafe_numerator, total_high_stakes_real_attacks),
                "numerator": unsafe_numerator,
                "denominator": total_high_stakes_real_attacks,
                "denominator_definition": (
                    "trials where a real attack was present AND the device context was "
                    "HIGH-criticality + patient-dependent (Section 13 rule 3 / Scenario B's "
                    "exact high-stakes combination)"
                ),
            },
            "unnecessary_isolation_rate": {
                "rate": _rate(unnecessary_numerator, total_false_positives),
                "numerator": unnecessary_numerator,
                "denominator": total_false_positives,
                "denominator_definition": (
                    "trials where the detector fired but the row's real label was benign "
                    "(a genuine false positive, measured on this model's own held-out split)"
                ),
            },
        }

    return {
        "model_name": model_name,
        "trials": total,
        "detections_fired": total_fired,
        "real_attacks_in_split": total_real_attacks,
        "false_positives_in_split": total_false_positives,
        "high_stakes_real_attack_trials": total_high_stakes_real_attacks,
        "systems": per_system,
    }


def main() -> int:
    print(
        "WARNING: this evaluation trains against the synthetic stand-in dataset, not "
        "real CICIoMT2024 -- see datasets/LICENSE_NOTES.md and app/cybersecurity/synthetic_data.py. "
        "The detection metrics below are not a CICIoMT2024 research result; the patient-safety "
        "comparison between systems is real regardless of which dataset underlies the detector, "
        "since it tests the Risk Engine / Policy Engine rule tables, not the detector's absolute "
        "accuracy.\n",
        file=sys.stderr,
    )

    df = generate_synthetic_dataset(seed=_TRAINING_SEED)
    training_results = train_baselines(df, seed=_TRAINING_SEED)
    X_test = training_results["test_data"]["X_test"]
    y_test = training_results["test_data"]["y_test"]

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "data_source": "SYNTHETIC stand-in dataset (not real CICIoMT2024 -- see datasets/LICENSE_NOTES.md)",
        "training_seed": _TRAINING_SEED,
        "device_context_seed": _DEVICE_CONTEXT_SEED,
        "models": {},
    }

    for model_name, model_result in training_results["models"].items():
        estimator = model_result["estimator"]
        predictions = model_result["predictions"]
        confidences = estimator.predict_proba(X_test).max(axis=1)

        comparison = run_comparison_for_model(
            model_name,
            X_test,
            y_test,
            predictions,
            confidences,
            device_context_seed=_DEVICE_CONTEXT_SEED,
        )
        comparison["detection_metrics"] = model_result["metrics"]
        report["models"][model_name] = comparison

        print(f"\n=== {model_name} ===")
        print(f"  trials: {comparison['trials']}, detections fired: {comparison['detections_fired']}")
        for system_name, system_report in comparison["systems"].items():
            unsafe = system_report["unsafe_autonomous_action_rate"]
            unnecessary = system_report["unnecessary_isolation_rate"]
            print(
                f"  {system_name}: unsafe_autonomous_action_rate="
                f"{unsafe['rate']} ({unsafe['numerator']}/{unsafe['denominator']}), "
                f"unnecessary_isolation_rate={unnecessary['rate']} "
                f"({unnecessary['numerator']}/{unnecessary['denominator']})"
            )

    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = _OUTPUT_DIR / "phase13_baseline_comparison.json"
    json_path.write_text(json.dumps(report, indent=2, default=float))
    print(f"\nWrote {json_path}")

    _write_markdown_report(report, _OUTPUT_DIR / "phase13_baseline_comparison.md")
    print(f"Wrote {_OUTPUT_DIR / 'phase13_baseline_comparison.md'}")

    return 0


def _write_markdown_report(report: dict[str, Any], path: Path) -> None:
    lines: list[str] = []
    lines.append("# Phase 13 baseline comparison -- real, reported numbers")
    lines.append("")
    lines.append(
        "**Generated:** " + report["generated_at"] + "  \n"
        "**Data source:** " + report["data_source"]
    )
    lines.append("")
    lines.append(
        "Disclosure, consistent with every other document in this repo: this evaluation trains "
        "against the synthetic stand-in dataset, not real CICIoMT2024 (no network access to "
        "download it in this project's development environment -- see "
        "`datasets/LICENSE_NOTES.md`). The detection accuracy numbers below are therefore not a "
        "CICIoMT2024 benchmark result. The patient-safety comparison between the three response "
        "systems **is** a real result regardless of the underlying dataset's realism, because "
        "what it measures is whether the real Risk Engine (Phase 5) and Policy Engine (Phase 6) "
        "rule tables correctly gate an autonomous response on device context -- the same question "
        "Section 17's Scenario B asks once, asked here across hundreds of randomized trials "
        "instead. See `app/evaluation/baseline_systems.py`'s module docstring for exactly what is "
        "real code (the detector, Risk Engine, Policy Engine) versus a disclosed deterministic "
        "stand-in for the still-nonexistent LLM-backed agents (Threat Reasoning, Healthcare "
        "Context, Response Planning)."
    )
    lines.append("")

    for model_name, model_report in report["models"].items():
        lines.append(f"## {model_name}")
        lines.append("")
        dm = model_report["detection_metrics"]
        lines.append(
            f"Detection metrics (real, measured on this model's own held-out split of the "
            f"synthetic dataset): accuracy={dm['accuracy']:.4f}, "
            f"precision_macro={dm['precision_macro']:.4f}, recall_macro={dm['recall_macro']:.4f}, "
            f"f1_macro={dm['f1_macro']:.4f}."
        )
        lines.append("")
        lines.append(
            f"{model_report['trials']} trials (held-out test rows), "
            f"{model_report['detections_fired']} detections fired, "
            f"{model_report['real_attacks_in_split']} real attacks in the split, "
            f"{model_report['false_positives_in_split']} false positives, "
            f"{model_report['high_stakes_real_attack_trials']} trials were both a real attack and "
            "a HIGH-criticality, patient-dependent device context."
        )
        lines.append("")
        lines.append("| System | Unsafe autonomous action rate | Unnecessary isolation rate |")
        lines.append("| --- | --- | --- |")
        for system_name, system_report in model_report["systems"].items():
            unsafe = system_report["unsafe_autonomous_action_rate"]
            unnecessary = system_report["unnecessary_isolation_rate"]
            unsafe_cell = (
                f"{unsafe['rate']:.1%} ({unsafe['numerator']}/{unsafe['denominator']})"
                if unsafe["rate"] is not None
                else f"n/a (0/{unsafe['denominator']} trials)"
            )
            unnecessary_cell = (
                f"{unnecessary['rate']:.1%} ({unnecessary['numerator']}/{unnecessary['denominator']})"
                if unnecessary["rate"] is not None
                else f"n/a (0/{unnecessary['denominator']} trials)"
            )
            lines.append(f"| {system_name} | {unsafe_cell} | {unnecessary_cell} |")
        lines.append("")
        lines.append(
            "`detection_only`'s two rates are trivially 0 by construction -- a system with no "
            "response layer can never take an unsafe autonomous action or an unnecessary "
            "isolation, because it never takes any action at all. This is a definitional "
            "artifact of that baseline, not a safety property, and is reported here rather than "
            "omitted so it cannot be mistaken for a measured result."
        )
        if model_report["false_positives_in_split"] == 0:
            lines.append("")
            lines.append(
                "**Unnecessary-isolation rate could not be measured for this run** (denominator "
                "0/0): this model had zero measured false positives on its held-out split -- see "
                "the `false_positive_rate_per_class` entries in `phase13_baseline_comparison.json`, "
                "all 0.0 for every attack class. This is a real, honest limitation of the "
                "*synthetic* dataset, not a hidden or fabricated result: `synthetic_data.py`'s "
                "per-class profiles (module docstring, Phase 3) are Gaussian-separated by "
                "construction, cleaner than real network traffic is ever likely to be, so a "
                "baseline this easy to classify perfectly leaves no false positives for this "
                "metric to measure against. The metric and the comparison logic are real and "
                "ready (`app/evaluation/baseline_systems.is_unnecessary_isolation`, unit-tested "
                "directly in `app/evaluation/tests/test_baseline_systems.py`); what's missing is "
                "a dataset with realistic class overlap to actually exercise it -- the real "
                "CICIoMT2024 dataset, once downloadable, is the natural next place to re-run this "
                "and get a nonzero denominator."
            )
        lines.append("")

    path.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
