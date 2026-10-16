"""Post-hoc probability calibration for the multiclass detector (numpy only).

Why: `evaluation/confidence_gating.md` showed the detector's softmax confidence
separates false alarms from real attacks, but XGBoost's raw probabilities are
not calibrated, so a threshold on them has no probabilistic meaning. Temperature
scaling is the simplest well-behaved fix: one scalar T > 0 fitted on held-out
validation data by minimising negative log-likelihood, applied as
p_i' ~ p_i ** (1 / T). It cannot change the predicted class (argmax is
unchanged), only the confidence attached to it.

Every function takes probabilities, not logits, because the saved XGBoost
`multi:softprob` model exposes probabilities. Probabilities are clipped away
from 0 before taking logs.
"""

from __future__ import annotations

import numpy as np

_EPS = 1e-12


def apply_temperature(proba: np.ndarray, temperature: float) -> np.ndarray:
    """Rescale rows of `proba` with temperature T; rows still sum to 1."""
    if temperature <= 0:
        raise ValueError("temperature must be positive")
    log_p = np.log(np.clip(proba, _EPS, 1.0)) / temperature
    log_p -= log_p.max(axis=1, keepdims=True)
    p = np.exp(log_p)
    return p / p.sum(axis=1, keepdims=True)


def negative_log_likelihood(proba: np.ndarray, y_idx: np.ndarray) -> float:
    return float(-np.log(np.clip(proba[np.arange(len(y_idx)), y_idx], _EPS, 1.0)).mean())


def fit_temperature(
    proba: np.ndarray, y_idx: np.ndarray, low: float = 0.05, high: float = 20.0, iters: int = 80
) -> float:
    """Temperature minimising validation NLL, by golden-section search on
    log T (NLL is unimodal in T for this family). Deterministic, no scipy."""
    phi = (np.sqrt(5) - 1) / 2
    a, b = np.log(low), np.log(high)

    def f(log_t: float) -> float:
        return negative_log_likelihood(apply_temperature(proba, float(np.exp(log_t))), y_idx)

    c, d = b - phi * (b - a), a + phi * (b - a)
    fc, fd = f(c), f(d)
    for _ in range(iters):
        if fc < fd:
            b, d, fd = d, c, fc
            c = b - phi * (b - a)
            fc = f(c)
        else:
            a, c, fc = c, d, fd
            d = a + phi * (b - a)
            fd = f(d)
    return float(np.exp((a + b) / 2))


def expected_calibration_error(confidence: np.ndarray, correct: np.ndarray, n_bins: int = 15) -> float:
    """Standard ECE: weighted mean |accuracy - confidence| over equal-width
    confidence bins."""
    confidence = np.asarray(confidence, dtype=float)
    correct = np.asarray(correct, dtype=float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bin_ids = np.clip(np.digitize(confidence, edges[1:-1], right=True), 0, n_bins - 1)
    ece = 0.0
    for b in range(n_bins):
        mask = bin_ids == b
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)
