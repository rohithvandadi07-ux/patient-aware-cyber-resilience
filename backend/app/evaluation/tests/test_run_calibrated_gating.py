import numpy as np

from app.evaluation.run_calibrated_gating import (
    MIN_RETENTION,
    NO_GATE,
    render_markdown,
    select_tau,
    sweep,
)
from app.evaluation.run_confidence_gating import TAU_GRID


def _row(tau, retention):
    return {"tau": tau, "real_attack_autonomous_retention": {"rate": retention}}


def test_select_tau_picks_the_largest_tau_meeting_the_retention_floor():
    rows = [
        _row(NO_GATE, 1.0),
        _row(0.6, 1.0),
        _row(0.8, 0.99),
        _row(0.9, 0.96),
        _row(0.95, 0.94),
        _row(0.99, 0.90),
    ]
    assert select_tau(rows) == 0.9


def test_select_tau_ignores_the_no_gate_row_and_falls_back_to_the_smallest_grid_tau():
    rows = [_row(NO_GATE, 1.0), _row(0.6, 0.5), _row(0.9, 0.4)]
    assert select_tau(rows) == min(TAU_GRID)
    assert select_tau([_row(0.6, None)]) == min(TAU_GRID)


def test_select_tau_boundary_is_inclusive():
    assert select_tau([_row(0.6, 1.0), _row(0.95, MIN_RETENTION)]) == 0.95


def _toy():
    n = 4000
    rng = np.random.default_rng(0)
    attack = rng.random(n) < 0.8
    true_h = np.where(attack, "dos", "unknown").astype(object)
    # detector mostly right; false alarms and some true attacks get lower confidence
    pred_h = np.where(attack | (rng.random(n) < 0.1), "dos", "unknown").astype(object)
    raw = np.where(attack, rng.uniform(0.85, 1.0, n), rng.uniform(0.6, 0.85, n)).astype(np.float32)
    return true_h, pred_h, raw


def test_sweep_is_monotone_and_never_unsafe_and_no_gate_row_is_the_baseline():
    true_h, pred_h, raw = _toy()
    rows = sweep(true_h, pred_h, raw, raw, seed_base=1, n_seeds=2, taus=[NO_GATE, 0.6, 0.9, 0.99])
    unnecessary = [r["unnecessary_isolation"]["rate"] for r in rows]
    retention = [r["real_attack_autonomous_retention"]["rate"] for r in rows]
    assert unnecessary == sorted(unnecessary, reverse=True)  # higher tau, fewer false-alarm isolations
    assert retention == sorted(retention, reverse=True)  # ... and less retained autonomy
    assert retention[0] == 1.0 and rows[1]["tau"] == 0.6 and retention[1] == 1.0  # raw conf >= 0.6
    assert all(r["unsafe_autonomous_action"]["rate"] in (0.0, None) for r in rows)


def test_render_markdown_mentions_the_selected_tau_and_the_validation_optimism_caveat():
    true_h, pred_h, raw = _toy()
    rows = sweep(true_h, pred_h, raw, raw, seed_base=1, n_seeds=1, taus=[NO_GATE, *TAU_GRID])
    block = {"rows": 10, "benign_rows": 2, "attack_rows": 8, "benign_false_positive_rate": 0.03}
    cal = {k: 0.1 for k in ("raw_nll", "cal_nll", "raw_ece", "cal_ece")}
    report = {
        "generated_at": "now",
        "min_retention": 0.95,
        "selected_tau": 0.9,
        "max_rows_per_class": 300000,
        "dev_model": {"train_rows": 5, "test_accuracy": 0.99},
        "calibration": {"temperature": 1.5, "validation": cal, "test": cal},
        "validation": {**block, "sweep": rows},
        "test": {**block, "sweep": rows},
    }
    text = render_markdown(report)
    assert "tau = 0.9" in text and "optimistic" in text and "(selected on validation)" in text
