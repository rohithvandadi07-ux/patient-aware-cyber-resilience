"""Calibrated confidence gate: choose tau on validation data, score the test split once.

`evaluation/confidence_gating.md` swept a confidence gate over the real test
split and, correctly, picked no threshold -- choosing one from curves drawn on
the test split would be tuning on test. This script does the part that needs
held-out data.

Protocol, fixed before running
------------------------------
1. Split the official TRAIN split into train and validation
   (`ciciomt2024.split_train_validation`): classes with several captures hold
   out their last capture whole; Benign and ARP_Spoofing, which have a single
   capture each, hold out a contiguous tail block with a gap. The official TEST
   split is not touched until step 6.
2. Train a fresh XGBoost on the reduced training portion (same hyperparameters
   and per-class cap as the shipped model). This "dev" model, not the shipped
   one, is what is calibrated and evaluated, because the shipped model has
   already seen the validation rows.
3. Fit one temperature T on validation (min NLL) -> calibrated confidence.
4. Detections still fire on the RAW confidence at the runtime threshold (0.6),
   so what the system detects is unchanged; the gate then looks at the
   CALIBRATED confidence.
5. Select tau on validation ONLY, by a rule written here before any result was
   seen: the largest tau in TAU_GRID whose validation real-attack-autonomy
   retention is at least MIN_RETENTION (95%). I.e. "remove as many false-alarm
   isolations as possible while still letting the system act on its own for at
   least 95% of the real attacks it would otherwise have handled."
6. Score the test split once with that tau (5 device-context seeds) and report
   it next to the whole test sweep. The test sweep is shown for transparency; it
   plays no part in the choice.
7. Report validation vs test for the same quantities. Benign and ARP_Spoofing
   validation rows come from the same capture as their training rows, so the
   validation false-alarm rate is expected to be optimistic; the gap is a
   finding, not something to hide.

Unsafe autonomous actions must be 0 for every tau and seed (the gate only
removes autonomy); the run asserts it.

Usage (from `backend/`):
    python -m app.evaluation.run_calibrated_gating --data-dir /path/to/iomt
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.cybersecurity.calibration import (
    apply_temperature,
    expected_calibration_error,
    fit_temperature,
    negative_log_likelihood,
)
from app.cybersecurity.ciciomt2024 import (
    CLASS_NAMES,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    cap_rows_per_class,
    class_counts,
    load_split,
    split_train_validation,
)
from app.cybersecurity.detection_service import DEFAULT_CONFIDENCE_THRESHOLD
from app.cybersecurity.train_ciciomt2024 import (
    DEFAULT_MAX_ROWS_PER_CLASS,
    DEFAULT_XGB,
    train_xgboost,
)
from app.evaluation.run_confidence_gating import TAU_GRID, baseline_pass, metrics_for_tau
from app.evaluation.run_real_data_comparison import harness_label

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "evaluation"
MIN_RETENTION = 0.95
VALIDATION_SEED_BASE = 31415
TEST_SEED_BASE = 2026  # same context seeds as run_real_data_comparison / run_confidence_gating
SEED_STRIDE = 7919
NO_GATE = 0.0  # tau 0 never demotes anything: the ungated system
_LABEL_TO_IDX = {c: i for i, c in enumerate(CLASS_NAMES)}


def predict_proba_all(model: Any, X: np.ndarray, batch: int = 200_000) -> np.ndarray:
    out = np.empty((len(X), len(CLASS_NAMES)), dtype=np.float32)
    for start in range(0, len(X), batch):
        out[start : start + batch] = model.predict_proba(X[start : start + batch])
    return out


def select_tau(validation_sweep: list[dict[str, Any]], min_retention: float = MIN_RETENTION) -> float:
    """The pre-declared rule: largest grid tau whose retention is >= min_retention.
    Falls back to the smallest grid tau if none qualifies (the gate then does the least
    it can), and says so in the report."""
    ok = [
        row["tau"]
        for row in validation_sweep
        if row["tau"] in TAU_GRID
        and row["real_attack_autonomous_retention"]["rate"] is not None
        and row["real_attack_autonomous_retention"]["rate"] >= min_retention
    ]
    return max(ok) if ok else min(TAU_GRID)


def _mean_rows(per_seed: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Collapse per-seed sweep rows to mean rates (+ min/max), keyed by tau."""
    out = []
    for j in range(len(per_seed[0])):
        rows = [seed_rows[j] for seed_rows in per_seed]
        entry: dict[str, Any] = {"tau": rows[0]["tau"]}
        for metric in (
            "unnecessary_isolation",
            "unsafe_autonomous_action",
            "real_attack_autonomous_retention",
        ):
            rates = [r[metric]["rate"] for r in rows if r[metric]["rate"] is not None]
            entry[metric] = {
                "rate": float(np.mean(rates)) if rates else None,
                "min": float(min(rates)) if rates else None,
                "max": float(max(rates)) if rates else None,
                "numerators_per_seed": [r[metric]["numerator"] for r in rows],
                "denominator": rows[0][metric]["denominator"],
            }
        entry["approvals_per_1000_detections"] = float(
            np.mean([r["approvals_added"]["per_1000_detections"] for r in rows])
        )
        out.append(entry)
    return out


def sweep(
    true_h: np.ndarray,
    pred_h: np.ndarray,
    raw_conf: np.ndarray,
    cal_conf: np.ndarray,
    *,
    seed_base: int,
    n_seeds: int,
    taus: list[float],
) -> list[dict[str, Any]]:
    per_seed = []
    for i in range(n_seeds):
        p = baseline_pass(true_h, pred_h, raw_conf, seed=seed_base + SEED_STRIDE * i, gate_conf=cal_conf)
        rows = [metrics_for_tau(p, tau) for tau in taus]
        if any(r["unsafe_autonomous_action"]["numerator"] != 0 for r in rows):
            raise AssertionError(
                "the gate produced an unsafe autonomous action; it must only remove autonomy"
            )
        per_seed.append(rows)
    return _mean_rows(per_seed)


def _pct(x: float | None, d: int = 1) -> str:
    return "n/a" if x is None else f"{x * 100:.{d}f}%"


def _cell(stat: dict[str, Any]) -> str:
    if stat["rate"] is None:
        return "n/a"
    if stat["min"] == stat["max"]:
        return _pct(stat["rate"])
    return f"{_pct(stat['rate'])} ({_pct(stat['min'])} to {_pct(stat['max'])})"


def _table(rows: list[dict[str, Any]], chosen: float | None) -> list[str]:
    lines = [
        "| tau (calibrated) | Unnecessary isolation (of false alarms) | Unsafe autonomous action "
        "| Real-attack autonomy retained | Extra approvals per 1,000 detections |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        label = "no gate" if r["tau"] == NO_GATE else f"{r['tau']}"
        if chosen is not None and r["tau"] == chosen:
            label += " **(selected on validation)**"
        lines.append(
            f"| {label} | {_cell(r['unnecessary_isolation'])} | {_cell(r['unsafe_autonomous_action'])} "
            f"| {_cell(r['real_attack_autonomous_retention'])} | {r['approvals_per_1000_detections']:.2f} |"
        )
    return lines


def _transfer_bullet(report: dict[str, Any]) -> str:
    """Compare retained real-attack autonomy on validation vs test at the same
    strict tau, and say which way the validation set misled the choice."""
    probe = 0.95
    v = next(r for r in report["validation"]["sweep"] if r["tau"] == probe)
    t = next(r for r in report["test"]["sweep"] if r["tau"] == probe)
    vr, tr = v["real_attack_autonomous_retention"]["rate"], t["real_attack_autonomous_retention"]["rate"]
    if vr is None or tr is None:
        return "- Validation-to-test transfer of real-attack autonomy could not be compared."
    if vr < tr - 0.05:
        verdict = (
            "validation was HARSHER than test for real attacks (the held-out validation captures are "
            "less confidently detected than the test captures), so a retention floor applied on "
            "validation picks a more conservative tau than the test split would have allowed"
        )
    elif vr > tr + 0.05:
        verdict = (
            "validation was MORE FAVOURABLE than test for real attacks, so the chosen tau gives up more "
            "real-attack autonomy on test than validation predicted"
        )
    else:
        verdict = "validation and test agree on how much real-attack autonomy a strict tau costs"
    return (
        f"- **Transfer check.** At tau {probe}, real-attack autonomy retained is {_pct(vr)} on validation "
        f"vs {_pct(tr)} on test: {verdict}. The false-alarm side moves the other way for the reason in "
        "the first bullet. Either way the headline number above is a single-split, single-model result."
    )


def render_markdown(report: dict[str, Any]) -> str:
    v, t, cal = report["validation"], report["test"], report["calibration"]
    chosen = report["selected_tau"]
    row = next(r for r in t["sweep"] if r["tau"] == chosen)
    none_row = next(r for r in t["sweep"] if r["tau"] == NO_GATE)
    lines = [
        "# Calibrated confidence gate: tau chosen on validation, scored once on test",
        "",
        f"Generated {report['generated_at']}. Experiment-only (the shipped Policy Engine gate is off by "
        "default and takes its threshold from `POLICY_MIN_AUTONOMOUS_CONFIDENCE`). Protocol and "
        "selection rule are in `backend/app/evaluation/run_calibrated_gating.py`'s docstring and were "
        "fixed before any result was seen.",
        "",
        "## Headline",
        "",
        f"The selection rule (largest tau keeping at least {_pct(report['min_retention'], 0)} of "
        f"real-attack autonomy **on validation**) chose **tau = {chosen}** on the calibrated "
        f"confidence. On the untouched test split that tau left "
        f"{_cell(row['unnecessary_isolation'])} of the detector's "
        f"{row['unnecessary_isolation']['denominator']:,} false alarms with autonomous action "
        f"(ungated: {_cell(none_row['unnecessary_isolation'])}), while the "
        f"system still acted on its own for {_cell(row['real_attack_autonomous_retention'])} of the real "
        f"attacks it would otherwise have handled, and unsafe autonomous actions stayed at "
        f"{_cell(row['unsafe_autonomous_action'])}.",
        "",
        "## Splits",
        "",
        f"* Dev-model training rows (after the per-class cap of {report['max_rows_per_class']:,}): "
        f"{report['dev_model']['train_rows']:,}.",
        f"* Validation rows: {v['rows']:,} (benign {v['benign_rows']:,}, attack {v['attack_rows']:,}).",
        f"* Test rows: {t['rows']:,} (benign {t['benign_rows']:,}, attack {t['attack_rows']:,}).",
        "* How each class was held out (see `validation.split_method` in the JSON): classes with "
        "several captures hold out their last capture whole; Benign and ARP_Spoofing (one capture "
        "each) hold out a contiguous tail block with a gap.",
        "",
        "## Detector and calibration",
        "",
        f"Dev model on the test split: 19-class accuracy {_pct(report['dev_model']['test_accuracy'], 2)}, "
        f"benign false-positive rate at the runtime threshold {_pct(t['benign_false_positive_rate'], 2)} "
        f"(validation: {_pct(v['benign_false_positive_rate'], 2)}).",
        "",
        f"Temperature fitted on validation: T = {cal['temperature']:.3f}.",
        "",
        "| | NLL | ECE (15 bins) |",
        "|---|---|---|",
        f"| validation, raw | {cal['validation']['raw_nll']:.4f} | {cal['validation']['raw_ece']:.4f} |",
        f"| validation, calibrated | {cal['validation']['cal_nll']:.4f} "
        f"| {cal['validation']['cal_ece']:.4f} |",
        f"| test, raw | {cal['test']['raw_nll']:.4f} | {cal['test']['raw_ece']:.4f} |",
        f"| test, calibrated | {cal['test']['cal_nll']:.4f} | {cal['test']['cal_ece']:.4f} |",
        "",
        "## Validation sweep (this is where tau was chosen)",
        "",
        *_table(v["sweep"], chosen),
        "",
        "Denominator of the unnecessary-isolation column: "
        f"{v['sweep'][0]['unnecessary_isolation']['denominator']:,} "
        "validation false alarms.",
        "",
        "## Test sweep (shown for transparency; played no part in the choice)",
        "",
        *_table(t["sweep"], chosen),
        "",
        f"Denominator: {t['sweep'][0]['unnecessary_isolation']['denominator']:,} test false alarms.",
        "",
        "## Reading this honestly",
        "",
        "- **Validation is optimistic for the classes that matter most here.** Benign and ARP_Spoofing "
        "have one training capture each, so their validation rows are a later stretch of the same "
        f"capture. Validation benign false-positive rate {_pct(v['benign_false_positive_rate'], 2)} vs test "
        f"{_pct(t['benign_false_positive_rate'], 2)} shows the size of that gap; a tau chosen on "
        "validation can transfer worse than the validation table suggests, and the test table is where "
        "to look for that.",
        _transfer_bullet(report),
        "- One detector training seed, one calibration fit, 5 device-context seeds; the contexts are "
        "sampled, not observed.",
        "- The false-alarm sample is small and concentrated in one predicted class (ARP_Spoofing), so "
        "the gate's benefit may largely be that class's weakness showing up in its confidence.",
        "- Temperature scaling fixes the confidence's scale, not the detector: the same rows are "
        "misclassified before and after. It does not make the detector robust to a different network.",
        "- The 95% retention floor is a policy choice (how much autonomy a hospital will trade for "
        "fewer false-alarm isolations), not a derived constant; the whole validation sweep is above so "
        "another floor can be read off.",
        "- In the live system the confidence given to the gate is the Threat Reasoning Agent's, which "
        "relays the detector's; a calibrated detector confidence would have to be threaded through "
        "from the detection event for the numbers here to apply as measured.",
    ]
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.time()

    def log(msg: str) -> None:
        print(f"[{time.time() - t0:5.0f}s] {msg}", flush=True)

    full_train = load_split(args.data_dir, "train")
    log(f"train split loaded: {len(full_train):,} rows")
    train_df, val_df, split_info = split_train_validation(full_train)
    del full_train
    log(f"split: train {len(train_df):,}, validation {len(val_df):,}")

    val_true19 = val_df[LABEL_COLUMN].to_numpy(dtype=object)
    X_val = val_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del val_df

    train_df = cap_rows_per_class(train_df, args.max_rows_per_class, seed=42)
    log(f"capped training rows: {len(train_df):,}")
    X_train = train_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_train = train_df[LABEL_COLUMN].to_numpy(dtype=object)
    train_counts = class_counts(train_df)
    del train_df

    model, _ = train_xgboost(X_train, y_train, {**DEFAULT_XGB}, seed=42, n_jobs=args.n_jobs)
    train_rows = len(X_train)
    del X_train, y_train
    log("dev model trained")
    if args.save_model:
        joblib.dump(model, args.save_model)

    val_proba = predict_proba_all(model, X_val)
    del X_val
    val_y = np.array([_LABEL_TO_IDX[x] for x in val_true19])
    temperature = fit_temperature(val_proba, val_y)
    val_cal = apply_temperature(val_proba, temperature)
    log(f"temperature fitted on validation: T={temperature:.3f}")

    test_df = load_split(args.data_dir, "test")
    test_true19 = test_df[LABEL_COLUMN].to_numpy(dtype=object)
    X_test = test_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del test_df
    test_proba = predict_proba_all(model, X_test)
    del X_test
    test_y = np.array([_LABEL_TO_IDX[x] for x in test_true19])
    test_cal = apply_temperature(test_proba, temperature)
    log("test predictions done (test not used for any choice)")

    def views(true19: np.ndarray, proba: np.ndarray, cal: np.ndarray, y: np.ndarray):
        pred_idx = proba.argmax(axis=1)
        pred19 = np.array([CLASS_NAMES[i] for i in pred_idx], dtype=object)
        true_h = np.array([harness_label(x) for x in true19], dtype=object)
        pred_h = np.array([harness_label(x) for x in pred19], dtype=object)
        raw_conf = proba.max(axis=1).astype(np.float32)
        cal_conf = cal.max(axis=1).astype(np.float32)
        return pred19, true_h, pred_h, raw_conf, cal_conf, pred_idx == y

    v_pred19, v_true_h, v_pred_h, v_raw, v_cal, v_correct = views(val_true19, val_proba, val_cal, val_y)
    t_pred19, t_true_h, t_pred_h, t_raw, t_cal, t_correct = views(test_true19, test_proba, test_cal, test_y)

    calibration = {
        "temperature": temperature,
        "validation": {
            "raw_nll": negative_log_likelihood(val_proba, val_y),
            "cal_nll": negative_log_likelihood(val_cal, val_y),
            "raw_ece": expected_calibration_error(v_raw, v_correct),
            "cal_ece": expected_calibration_error(v_cal, v_correct),
        },
        "test": {
            "raw_nll": negative_log_likelihood(test_proba, test_y),
            "cal_nll": negative_log_likelihood(test_cal, test_y),
            "raw_ece": expected_calibration_error(t_raw, t_correct),
            "cal_ece": expected_calibration_error(t_cal, t_correct),
        },
    }

    def detector_stats(true_h: np.ndarray, pred_h: np.ndarray, raw: np.ndarray) -> dict[str, Any]:
        fired = (pred_h != "unknown") & (raw >= DEFAULT_CONFIDENCE_THRESHOLD)
        attack = true_h != "unknown"
        return {
            "rows": int(len(true_h)),
            "benign_rows": int((~attack).sum()),
            "attack_rows": int(attack.sum()),
            "false_positives": int((fired & ~attack).sum()),
            "benign_false_positive_rate": float((fired & ~attack).sum() / max((~attack).sum(), 1)),
            "attack_detection_rate": float((fired & attack).sum() / max(attack.sum(), 1)),
        }

    taus = [NO_GATE, *TAU_GRID]
    val_sweep = sweep(
        v_true_h, v_pred_h, v_raw, v_cal, seed_base=VALIDATION_SEED_BASE, n_seeds=args.n_seeds, taus=taus
    )
    chosen = select_tau(val_sweep)
    log(f"validation sweep done; selected tau = {chosen} (rule fixed in advance)")

    test_sweep = sweep(
        t_true_h, t_pred_h, t_raw, t_cal, seed_base=TEST_SEED_BASE, n_seeds=args.n_seeds, taus=taus
    )
    log("test sweep done")

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "min_retention": MIN_RETENTION,
        "selection_rule": (
            f"largest tau in {TAU_GRID} with validation real-attack autonomy retention >= {MIN_RETENTION}"
        ),
        "selected_tau": chosen,
        "max_rows_per_class": args.max_rows_per_class,
        "dev_model": {
            "hyperparameters": DEFAULT_XGB,
            "train_rows": int(train_rows),
            "train_class_counts": train_counts,
            "test_accuracy": float((t_pred19 == test_true19).mean()),
        },
        "calibration": calibration,
        "validation": {
            **detector_stats(v_true_h, v_pred_h, v_raw),
            "split_method": split_info,
            "seeds": [VALIDATION_SEED_BASE + SEED_STRIDE * i for i in range(args.n_seeds)],
            "sweep": val_sweep,
        },
        "test": {
            **detector_stats(t_true_h, t_pred_h, t_raw),
            "seeds": [TEST_SEED_BASE + SEED_STRIDE * i for i in range(args.n_seeds)],
            "sweep": test_sweep,
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "calibrated_gating.json").write_text(json.dumps(report, indent=2, default=float))
    (args.output_dir / "calibrated_gating.md").write_text(render_markdown(report))
    log(f"wrote reports to {args.output_dir}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, required=True, help="Folder containing train/ and test/.")
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--max-rows-per-class", type=int, default=DEFAULT_MAX_ROWS_PER_CLASS)
    parser.add_argument("--n-seeds", type=int, default=5)
    parser.add_argument("--n-jobs", type=int, default=2)
    parser.add_argument("--save-model", type=Path, default=None, help="Optionally save the dev model here.")
    args = parser.parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
