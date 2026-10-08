"""Detection-task validity guards.

These tests exist to prevent a specific, publication-invalidating failure
mode: a simulator that plants a signal only the attack path produces. When
that happens, a single feature separates the classes perfectly, any
classifier reports F1 near 1.0, and the reported metrics are meaningless.

The guards below fail loudly, naming the offending feature, if a future
change reintroduces such a signal. See docs/detection-validity.md.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from backend.app.domain.ids import IdFactory
from cybersecurity.features.extractor import WindowedFeatureExtractor
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import (
    PRIMARY_DETECTION_CORPUS,
    STEALTH_SCENARIOS,
    get_scenario,
)

pytestmark = pytest.mark.unit

#: A single feature may not exceed this AUC on the primary corpus. Above it,
#: the task is solvable by one threshold and the corpus is degenerate.
PRIMARY_CORPUS_MAX_SINGLE_AUC = 0.90

#: Stealth scenarios are individually easier than the mixed corpus (one
#: attack type, one device), so the bar is looser but still non-degenerate.
STEALTH_MAX_SINGLE_AUC = 0.98


def _windows(scenario: str, ticks: int | None = None, device_id: str | None = None):
    spec = get_scenario(scenario)
    hospital = SmartHospital(scenario=spec, ids=IdFactory(deterministic=True))
    events = hospital.run(ticks or spec.total_ticks)
    windows = WindowedFeatureExtractor(window_seconds=5.0).extract(events)
    if device_id:
        windows = [w for w in windows if w.device_id == device_id]
    return windows


def _single_feature_aucs(windows) -> list[tuple[float, str]]:
    """Univariate AUC for every feature, orientation-independent."""
    y = np.array([w.y_binary for w in windows])
    if len(set(y.tolist())) < 2:
        return []
    names = sorted({k for w in windows for k in w.features})
    out: list[tuple[float, str]] = []
    for name in names:
        x = np.array([w.features.get(name, 0.0) for w in windows])
        if x.min() == x.max():
            continue
        auc = roc_auc_score(y, x)
        out.append((max(auc, 1.0 - auc), name))
    out.sort(reverse=True)
    return out


class TestPrimaryCorpusIsNotDegenerate:
    """The corpus detection is trained and evaluated on must need a model."""

    def test_no_single_feature_solves_the_task(self) -> None:
        windows = _windows(PRIMARY_DETECTION_CORPUS)
        aucs = _single_feature_aucs(windows)
        assert aucs, "corpus produced no usable feature variance"
        worst_auc, worst_feature = aucs[0]
        assert worst_auc <= PRIMARY_CORPUS_MAX_SINGLE_AUC, (
            f"Feature {worst_feature!r} alone achieves AUC {worst_auc:.3f} on the "
            f"primary corpus, above the {PRIMARY_CORPUS_MAX_SINGLE_AUC} limit. The "
            "detection task is degenerate: a single threshold separates the "
            "classes, so any reported metric is meaningless. A benign path "
            "almost certainly fails to produce this signal at all. "
            "See docs/detection-validity.md."
        )

    def test_class_imbalance_is_realistic(self) -> None:
        """A balanced corpus would also be unrealistically easy."""
        windows = _windows(PRIMARY_DETECTION_CORPUS)
        rate = sum(w.y_binary for w in windows) / len(windows)
        assert 0.02 <= rate <= 0.30, (
            f"attack prevalence {rate:.1%} is unrealistic for a hospital network; "
            "expected a minority class in the 2-30% range"
        )

    def test_corpus_spans_a_range_of_attack_intensities(self) -> None:
        spec = get_scenario(PRIMARY_DETECTION_CORPUS)
        intensities = {a.intensity for a in spec.attack_specs}
        assert min(intensities) <= 0.15, "corpus lacks stealth-intensity attacks"
        assert max(intensities) >= 0.9, "corpus lacks high-intensity attacks"
        assert len(intensities) >= 4, "corpus needs a spread of intensities"

    def test_benign_windows_exercise_the_attack_feature_dimensions(self) -> None:
        """Benign traffic must occupy the dimensions attacks elevate.

        If a feature is identically zero across all benign windows, its mere
        presence is the label.
        """
        windows = _windows(PRIMARY_DETECTION_CORPUS)
        benign = [w for w in windows if w.y_binary == 0]
        assert benign
        must_vary = (
            "rtt_ms",
            "ttl_variance",
            "syn_ratio",
            "distinct_dst_ports",
            "arp_table_changes",
            "duplicate_mac_observed",
            "is_arp",
            "is_udp",
        )
        degenerate = []
        for name in must_vary:
            vals = [w.features.get(name, 0.0) for w in benign]
            if max(vals) <= 0.0:
                degenerate.append(name)
        assert degenerate == [], (
            f"features {degenerate} are identically zero in ALL benign windows, "
            "making their presence an attack label. Benign traffic must "
            "legitimately produce these signals."
        )


class TestStealthScenariosAreHard:
    @pytest.mark.parametrize("scenario", STEALTH_SCENARIOS)
    def test_stealth_attacks_are_not_trivially_separable(self, scenario: str) -> None:
        windows = _windows(scenario)
        aucs = _single_feature_aucs(windows)
        if not aucs:
            pytest.skip(f"{scenario} produced no label variance")
        worst_auc, worst_feature = aucs[0]
        assert worst_auc <= STEALTH_MAX_SINGLE_AUC, (
            f"{scenario}: feature {worst_feature!r} alone achieves AUC "
            f"{worst_auc:.3f}. A stealth attack separable by one feature is not "
            "stealthy; the benign path likely never produces this signal."
        )

    @pytest.mark.parametrize("scenario", STEALTH_SCENARIOS)
    def test_stealth_scenarios_use_low_intensity(self, scenario: str) -> None:
        spec = get_scenario(scenario)
        assert spec.attack_specs
        assert max(a.intensity for a in spec.attack_specs) <= 0.2, (
            "a stealth scenario must use low attack intensity"
        )


class TestLeakageGuardsHold:
    def test_no_truth_channel_reaches_the_feature_matrix(self) -> None:
        """The simulator's internal-truth channels must never be features."""
        windows = _windows("s2_ventilator_compromise")
        for w in windows:
            for name in w.features:
                assert not name.startswith("truth_"), (
                    f"feature {name!r} exposes the simulator's ground-truth "
                    "channel; detection would be trivially and dishonestly easy"
                )

    def test_no_identity_feature_reaches_the_feature_matrix(self) -> None:
        from cybersecurity.schema import FORBIDDEN_FEATURES

        windows = _windows("mixed_difficulty_corpus", ticks=120)
        for w in windows:
            leaked = set(w.features) & FORBIDDEN_FEATURES
            assert not leaked, f"forbidden features present: {sorted(leaked)}"

    def test_spoofed_telemetry_is_not_detectable_from_reported_vitals_alone(
        self,
    ) -> None:
        """Spoofing must be caught by residual/variance structure.

        Under telemetry spoofing the reported vitals look healthy. If the
        reported value alone separated the classes, the simulator would be
        leaking the deterioration it is supposed to be hiding.
        """
        windows = _windows("s2_ventilator_compromise", device_id="VENT-ICU-01")
        y = np.array([w.y_binary for w in windows])
        if len(set(y.tolist())) < 2:
            pytest.skip("no label variance")
        # 'telemetry_residual' is a legitimate derived signal; the guard is
        # that no RAW reported vital is itself a near-perfect separator.
        for name in ("spo2_pct", "respiratory_rate", "tidal_volume_ml"):
            vals = [w.features.get(name) for w in windows]
            assert all(v is None for v in vals), (
                f"raw vital {name!r} leaked into the feature matrix; spoofing "
                "detection must rely on residual structure, not raw vitals"
            )
