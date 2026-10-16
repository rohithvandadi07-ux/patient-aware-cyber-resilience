import numpy as np
import pytest

from app.cybersecurity.calibration import (
    apply_temperature,
    expected_calibration_error,
    fit_temperature,
    negative_log_likelihood,
)


def _overconfident(n=4000, k=5, seed=0):
    """Labels drawn from p, but the model reports a sharpened p (T_true = 2)."""
    rng = np.random.default_rng(seed)
    logits = rng.normal(0, 1.2, (n, k))
    true_p = np.exp(logits) / np.exp(logits).sum(1, keepdims=True)
    y = np.array([rng.choice(k, p=row) for row in true_p])
    return apply_temperature(true_p, 0.5), y  # T=0.5 sharpens


def test_temperature_one_is_the_identity_and_rows_stay_normalised():
    p = np.array([[0.7, 0.2, 0.1], [0.1, 0.1, 0.8]])
    np.testing.assert_allclose(apply_temperature(p, 1.0), p, atol=1e-9)
    assert np.allclose(apply_temperature(p, 3.0).sum(1), 1.0)


def test_higher_temperature_lowers_confidence_and_keeps_the_argmax():
    p = np.array([[0.7, 0.2, 0.1]])
    soft = apply_temperature(p, 2.0)
    assert soft.max() < p.max() and soft.argmax() == p.argmax()
    with pytest.raises(ValueError):
        apply_temperature(p, 0.0)


def test_fit_temperature_recovers_overconfidence_and_improves_nll_and_ece():
    proba, y = _overconfident()
    t = fit_temperature(proba, y)
    assert t == pytest.approx(2.0, rel=0.15)  # undoes the 0.5 sharpening
    calibrated = apply_temperature(proba, t)
    assert negative_log_likelihood(calibrated, y) < negative_log_likelihood(proba, y)
    correct = proba.argmax(1) == y
    assert expected_calibration_error(calibrated.max(1), correct) < expected_calibration_error(
        proba.max(1), correct
    )


def test_ece_is_zero_for_perfectly_calibrated_and_large_for_overconfident():
    conf = np.full(1000, 0.8)
    correct = np.array([True] * 800 + [False] * 200)
    assert expected_calibration_error(conf, correct) == pytest.approx(0.0, abs=1e-9)
    assert expected_calibration_error(np.full(1000, 0.99), correct) > 0.15
