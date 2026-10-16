"""Tests for the real-data comparison runner's glue code (label mapping, count
merging, summary). The decision logic itself is covered by
`test_baseline_systems.py`; the real 1.6M-row run is the script itself, reported
in `evaluation/real_data_comparison.md`."""

import numpy as np
import pytest

from app.cybersecurity.ciciomt2024 import CLASS_NAMES
from app.evaluation.run_real_data_comparison import (
    _finalize,
    _merge,
    compare_all_rows,
    harness_label,
    render_markdown,
    summarize,
)


def test_every_real_class_maps_to_a_harness_label_and_only_benign_is_unknown():
    for label in CLASS_NAMES:
        mapped = harness_label(label)
        assert (mapped == "unknown") == (label == "Benign")


def test_merge_sums_counts_and_finalize_recomputes_rates():
    a = {"trials": 10, "x": {"numerator": 1, "denominator": 4, "rate": 0.25, "note": "n"}}
    b = {"trials": 5, "x": {"numerator": 2, "denominator": 4, "rate": 0.5, "note": "n"}}
    out = _finalize(_merge(a, b))
    assert out["trials"] == 15
    assert out["x"]["numerator"] == 3 and out["x"]["denominator"] == 8
    assert out["x"]["rate"] == pytest.approx(3 / 8)
    assert out["x"]["note"] == "n"


def test_finalize_gives_none_rate_for_zero_denominator():
    out = _finalize({"x": {"numerator": 0, "denominator": 0, "rate": 0.0}})
    assert out["x"]["rate"] is None


def _fake_rows(n=600, seed=0):
    rng = np.random.default_rng(seed)
    true = np.where(rng.random(n) < 0.15, "unknown", "ddos").astype(object)
    pred = true.copy()
    flip = rng.random(n) < 0.05
    pred[flip] = np.where(true[flip] == "unknown", "ddos", "unknown")
    conf = rng.uniform(0.7, 1.0, n).astype(np.float32)
    return true, pred, conf


def test_chunked_comparison_equals_single_chunk_totals_and_is_reproducible():
    true, pred, conf = _fake_rows()
    a = compare_all_rows(true, pred, conf, seed=1, chunk=200)
    b = compare_all_rows(true, pred, conf, seed=1, chunk=200)
    assert a == b
    assert a["trials"] == 600
    assert a["real_attacks_in_split"] == int((true != "unknown").sum())


def test_full_system_never_acts_unsafely_but_fixed_response_does():
    true, pred, conf = _fake_rows(n=3000, seed=3)
    r = compare_all_rows(true, pred, conf, seed=5, chunk=1000)
    full = r["systems"]["full_system"]["unsafe_autonomous_action_rate"]
    fixed = r["systems"]["fixed_response"]["unsafe_autonomous_action_rate"]
    assert full["denominator"] > 0
    assert full["numerator"] == 0
    assert fixed["numerator"] > 0


def test_summary_and_markdown_render():
    true, pred, conf = _fake_rows(n=900, seed=2)
    per_seed = [compare_all_rows(true, pred, conf, seed=s, chunk=300) for s in (1, 2)]
    summary = summarize(per_seed)
    assert set(summary["systems"]) >= {"full_system", "fixed_response", "detection_only"}
    report = {
        "generated_at": "t",
        "trials": 900,
        "seeds": [1, 2],
        "confidence_threshold": 0.6,
        "detector_at_threshold": {
            "detections_fired": 1,
            "real_attacks": 2,
            "benign_rows": 3,
            "false_positives": 0,
            "attack_detection_rate": 0.5,
            "benign_false_positive_rate": 0.0,
        },
        "per_seed": per_seed,
        "summary": summary,
    }
    md = render_markdown(report)
    assert "## Five systems" in md and "## Six ablations" in md
