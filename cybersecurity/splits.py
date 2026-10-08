"""Train/test split protocols and threshold calibration.

WHY THIS MODULE EXISTS
----------------------
Two methodological errors were measured during development and are prevented
here, because both would have produced misleading published numbers.

**1. An uncalibrated decision threshold.** A random forest reached ROC-AUC
0.777 yet predicted *zero* attacks, giving F1 = 0.000. Nothing was wrong with
the model: it ranked correctly, but the default 0.5 threshold is simply wrong
at 7% attack prevalence. Reporting F1 at a default threshold measures the
threshold, not the model. :func:`calibrate_threshold` selects it on a
validation fold carved from training data, never on test.

**2. A naive temporal split leaking the task.** Splitting the primary corpus
at 70% of elapsed time put ``malicious_command`` *only* in test and
``ddos``/``port_scan`` *only* in train. The resulting score measures
zero-day generalisation, which is a different and much harder research
question. Both are legitimate experiments; conflating them is not.

Three protocols are therefore provided and reported separately:

``grouped``       - attack episodes kept intact, stratified across folds.
                    The headline protocol for standard detection.
``temporal``      - strict time order, for deployment realism.
``unseen_attack`` - a named attack family held out entirely, for explicit
                    zero-day evaluation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

import numpy as np

from cybersecurity.features.extractor import FeatureWindow

SplitName = Literal["grouped", "temporal", "unseen_attack"]


@dataclass
class SplitResult:
    """A split, with the provenance needed to report it honestly."""

    protocol: str
    train: list[FeatureWindow]
    test: list[FeatureWindow]
    validation: list[FeatureWindow] = field(default_factory=list)
    held_out_attack: str | None = None
    notes: str = ""

    @property
    def summary(self) -> dict[str, object]:
        def stats(ws: list[FeatureWindow]) -> dict[str, object]:
            n = len(ws)
            atk = sum(w.y_binary for w in ws)
            return {
                "n": n,
                "attack": atk,
                "prevalence": round(atk / n, 4) if n else 0.0,
                "attack_types": sorted({w.y_attack_type for w in ws if w.y_binary}),
            }

        return {
            "protocol": self.protocol,
            "held_out_attack": self.held_out_attack,
            "train": stats(self.train),
            "validation": stats(self.validation),
            "test": stats(self.test),
            "notes": self.notes,
        }

    def assert_usable(self) -> None:
        """Fail loudly on a split that cannot support a meaningful metric."""
        for part_name in ("train", "test"):
            part = getattr(self, part_name)
            if not part:
                raise ValueError(f"{self.protocol}: {part_name} split is empty")
            if len({w.y_binary for w in part}) < 2:
                raise ValueError(
                    f"{self.protocol}: {part_name} split contains a single class, "
                    "so no meaningful detection metric can be computed"
                )


def _episodes(windows: Sequence[FeatureWindow]) -> list[list[int]]:
    """Group windows into contiguous same-label episodes.

    Episodes are the correct grouping unit: adjacent windows of one attack
    are highly correlated, so splitting mid-episode leaks near-duplicate
    rows across the boundary and inflates scores.
    """
    order = sorted(
        range(len(windows)), key=lambda i: (windows[i].window_start, windows[i].device_id)
    )
    groups: list[list[int]] = []
    current: list[int] = []
    key: tuple | None = None
    for i in order:
        w = windows[i]
        k = (w.device_id, w.y_binary, w.y_attack_type)
        if k != key:
            if current:
                groups.append(current)
            current = [i]
            key = k
        else:
            current.append(i)
    if current:
        groups.append(current)
    return groups


def grouped_split(
    windows: list[FeatureWindow],
    test_fraction: float = 0.3,
    validation_fraction: float = 0.15,
    seed: int = 20260101,
) -> SplitResult:
    """Episode-grouped, attack-type-stratified split.

    Whole attack episodes go to one side of the boundary, and each attack
    type is represented on both sides, so the metric measures detection
    rather than extrapolation to an unseen family.
    """
    rng = np.random.default_rng(seed)
    groups = _episodes(windows)

    by_type: dict[str, list[list[int]]] = {}
    for g in groups:
        t = windows[g[0]].y_attack_type if windows[g[0]].y_binary else "benign"
        by_type.setdefault(t, []).append(g)

    train_idx: list[int] = []
    val_idx: list[int] = []
    test_idx: list[int] = []

    for t, gs in sorted(by_type.items()):
        order = rng.permutation(len(gs))
        shuffled = [gs[i] for i in order]
        n = len(shuffled)
        if n == 1 and t != "benign":
            # A single episode of this type cannot appear on both sides.
            # Put it in train so the model has seen the family, and record
            # the limitation rather than silently producing a test set with
            # an unseen class.
            train_idx.extend(shuffled[0])
            continue
        n_test = max(1, round(n * test_fraction))
        n_val = round(n * validation_fraction)
        test_groups = shuffled[:n_test]
        val_groups = shuffled[n_test : n_test + n_val]
        train_groups = shuffled[n_test + n_val :]
        if not train_groups:
            train_groups, test_groups = test_groups, train_groups
        for g in test_groups:
            test_idx.extend(g)
        for g in val_groups:
            val_idx.extend(g)
        for g in train_groups:
            train_idx.extend(g)

    single = [t for t, gs in by_type.items() if len(gs) == 1 and t != "benign"]
    note = (
        "Episode-grouped and attack-type-stratified: whole attack episodes are "
        "assigned to one side, and each type with 2+ episodes appears on both."
    )
    if single:
        note += f" Types with only one episode kept in train (cannot be split): {sorted(single)}."

    return SplitResult(
        protocol="grouped",
        train=[windows[i] for i in sorted(train_idx)],
        validation=[windows[i] for i in sorted(val_idx)],
        test=[windows[i] for i in sorted(test_idx)],
        notes=note,
    )


def temporal_split(
    windows: list[FeatureWindow],
    test_fraction: float = 0.3,
    validation_fraction: float = 0.1,
) -> SplitResult:
    """Strict chronological split: train on the past, test on the future.

    The most deployment-realistic protocol, but on a corpus where attack
    types are introduced sequentially it also measures generalisation to
    unseen families. The returned ``notes`` names any type present on only
    one side, so the limitation is reported rather than hidden.
    """
    ordered = sorted(windows, key=lambda w: (w.window_start, w.device_id))
    n = len(ordered)
    n_test = round(n * test_fraction)
    n_val = round(n * validation_fraction)
    cut_test = n - n_test
    cut_val = cut_test - n_val
    train = ordered[:cut_val]
    val = ordered[cut_val:cut_test]
    test = ordered[cut_test:]

    train_types = {w.y_attack_type for w in train if w.y_binary}
    test_types = {w.y_attack_type for w in test if w.y_binary}
    unseen = sorted(test_types - train_types)
    absent = sorted(train_types - test_types)
    note = "Strict chronological order: train on the past, test on the future."
    if unseen:
        note += (
            f" NOTE: attack types {unseen} appear ONLY in test, so this score "
            "partly measures generalisation to unseen attack families, not "
            "standard detection."
        )
    if absent:
        note += f" Types {absent} appear only in train."
    return SplitResult(protocol="temporal", train=train, validation=val, test=test, notes=note)


def unseen_attack_split(
    windows: list[FeatureWindow],
    held_out_attack: str,
    validation_fraction: float = 0.15,
    seed: int = 20260101,
) -> SplitResult:
    """Hold out one attack family entirely: explicit zero-day evaluation.

    Benign traffic is shared across both sides; every window of the held-out
    family goes to test. Measures whether the detector flags a family it has
    never seen.
    """
    rng = np.random.default_rng(seed)
    held = [w for w in windows if w.y_binary and w.y_attack_type == held_out_attack]
    if not held:
        raise ValueError(f"no windows for attack type {held_out_attack!r}")
    other_attacks = [w for w in windows if w.y_binary and w.y_attack_type != held_out_attack]
    benign = [w for w in windows if not w.y_binary]

    order = rng.permutation(len(benign))
    n_test_benign = max(1, len(benign) // 3)
    test_benign = [benign[i] for i in order[:n_test_benign]]
    rest_benign = [benign[i] for i in order[n_test_benign:]]
    n_val = round(len(rest_benign) * validation_fraction)
    val = rest_benign[:n_val]
    train_benign = rest_benign[n_val:]

    return SplitResult(
        protocol="unseen_attack",
        train=sorted(train_benign + other_attacks, key=lambda w: w.window_start),
        validation=sorted(val, key=lambda w: w.window_start),
        test=sorted(test_benign + held, key=lambda w: w.window_start),
        held_out_attack=held_out_attack,
        notes=(
            f"Attack family {held_out_attack!r} held out of training entirely. "
            "This is a zero-day generalisation measurement and must be reported "
            "separately from standard detection results."
        ),
    )


def make_split(
    protocol: SplitName,
    windows: list[FeatureWindow],
    held_out_attack: str | None = None,
    seed: int = 20260101,
    **kwargs: float,
) -> SplitResult:
    if protocol == "grouped":
        return grouped_split(windows, seed=seed, **kwargs)
    if protocol == "temporal":
        return temporal_split(windows, **kwargs)
    if protocol == "unseen_attack":
        if not held_out_attack:
            raise ValueError("unseen_attack protocol requires held_out_attack")
        return unseen_attack_split(windows, held_out_attack, seed=seed, **kwargs)
    raise ValueError(f"unknown split protocol {protocol!r}")


# ---------------------------------------------------------------------------
# Threshold calibration
# ---------------------------------------------------------------------------
@dataclass
class ThresholdChoice:
    threshold: float
    objective: str
    achieved: dict[str, float]
    n_validation: int
    note: str = ""


def calibrate_threshold(
    y_true: Sequence[int],
    y_prob: Sequence[float],
    objective: str = "max_f1",
    max_fpr: float = 0.05,
    min_recall: float = 0.80,
) -> ThresholdChoice:
    """Choose a decision threshold on validation data.

    Objectives:

    ``max_f1``            maximise F1.
    ``max_recall_at_fpr`` maximise recall subject to FPR <= ``max_fpr``. The
                          operationally right choice for a hospital SOC,
                          where alert fatigue is the binding constraint.
    ``min_fpr_at_recall`` minimise FPR subject to recall >= ``min_recall``.

    NEVER call this on test data. Doing so is threshold-tuning on the test
    set and inflates every reported metric.
    """
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(y_prob, dtype=float)
    if len(set(y.tolist())) < 2:
        return ThresholdChoice(
            threshold=0.5,
            objective=objective,
            achieved={},
            n_validation=len(y),
            note="validation fold has a single class; falling back to 0.5",
        )

    candidates = np.unique(np.concatenate([p, np.linspace(0.01, 0.99, 99)]))
    best: tuple[float, float, dict[str, float]] | None = None

    for t in candidates:
        pred = (p >= t).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }

        if objective == "max_f1":
            score = f1
        elif objective == "max_recall_at_fpr":
            score = recall if fpr <= max_fpr else -1.0
        elif objective == "min_fpr_at_recall":
            score = -fpr if recall >= min_recall else -1e9
        else:
            raise ValueError(f"unknown objective {objective!r}")

        if best is None or score > best[1]:
            best = (float(t), score, metrics)

    assert best is not None
    threshold, score, metrics = best
    note = ""
    if score < 0:
        threshold = 0.5
        note = (
            f"no threshold satisfied the {objective} constraint on validation; "
            "falling back to 0.5. Report this - it means the model cannot meet "
            "the operating requirement."
        )
    elif metrics["recall"] <= 0.0 or metrics["precision"] <= 0.0:
        # A constraint can be satisfied degenerately: predicting nothing gives
        # FPR 0 and so "meets" an FPR ceiling while detecting no attack at all.
        # That is a failure to report, not an operating point to ship.
        note = (
            f"the {objective} constraint was satisfied only degenerately "
            f"(recall={metrics['recall']}, precision={metrics['precision']}): the "
            "selected threshold detects essentially nothing. The model cannot "
            "meet this operating requirement; do not report this as a result."
        )
    return ThresholdChoice(
        threshold=threshold,
        objective=objective,
        achieved=metrics,
        n_validation=len(y),
        note=note,
    )


__all__ = [
    "SplitName",
    "SplitResult",
    "ThresholdChoice",
    "calibrate_threshold",
    "grouped_split",
    "make_split",
    "temporal_split",
    "unseen_attack_split",
]
