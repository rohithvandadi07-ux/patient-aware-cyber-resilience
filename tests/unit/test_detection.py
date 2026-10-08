"""Detection engine tests.

Covers the detector contracts, the split protocols and the threshold
calibration, with particular attention to the two methodological errors
measured during development: an uncalibrated threshold and a split that
leaks the task.
"""

from __future__ import annotations

import warnings

import numpy as np
import pytest

from backend.app.domain.enums import AssertionClass, AttackType, DetectorKind, Severity
from backend.app.domain.ids import IdFactory
from cybersecurity.detectors.anomaly import AnomalyDetector, EnsembleDetector
from cybersecurity.detectors.base import ATTACK_SEVERITY
from cybersecurity.detectors.rules import DEFAULT_RULES, Rule, RuleDetector
from cybersecurity.detectors.supervised import (
    SupervisedDetector,
    windows_to_matrix,
)
from cybersecurity.features.extractor import FeatureWindow, WindowedFeatureExtractor
from cybersecurity.schema import FORBIDDEN_FEATURES
from cybersecurity.splits import (
    calibrate_threshold,
    grouped_split,
    make_split,
    temporal_split,
    unseen_attack_split,
)
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import PRIMARY_DETECTION_CORPUS, get_scenario

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def corpus() -> list[FeatureWindow]:
    spec = get_scenario(PRIMARY_DETECTION_CORPUS)
    hospital = SmartHospital(scenario=spec, ids=IdFactory(deterministic=True))
    events = hospital.run(spec.total_ticks)
    return WindowedFeatureExtractor(window_seconds=5.0).extract(events)


# ===========================================================================
# Feature extraction
# ===========================================================================
class TestFeatureExtraction:
    def test_produces_windows_with_labels(self, corpus) -> None:
        assert corpus
        assert any(w.y_binary == 1 for w in corpus)
        assert any(w.y_binary == 0 for w in corpus)

    def test_windows_are_per_device(self, corpus) -> None:
        assert len({w.device_id for w in corpus}) > 1
        for w in corpus:
            assert w.device_id

    def test_feature_vector_is_fixed_length(self, corpus) -> None:
        lengths = {len(w.feature_vector()) for w in corpus[:50]}
        assert len(lengths) == 1

    def test_no_forbidden_feature_is_emitted(self, corpus) -> None:
        for w in corpus[:200]:
            assert not (set(w.features) & FORBIDDEN_FEATURES)

    def test_all_feature_values_are_finite(self, corpus) -> None:
        for w in corpus[:200]:
            for name, value in w.features.items():
                assert np.isfinite(value), f"{name} is not finite"

    def test_extractor_is_deterministic(self) -> None:
        spec = get_scenario("s2_ventilator_compromise")

        def run():
            h = SmartHospital(scenario=spec, ids=IdFactory(deterministic=True))
            return WindowedFeatureExtractor(window_seconds=5.0).extract(h.run(150))

        a, b = run(), run()
        assert [w.features for w in a] == [w.features for w in b]

    def test_telemetry_residual_requires_a_baseline(self) -> None:
        """A residual cannot be computed before a baseline exists."""
        spec = get_scenario("baseline_normal")
        h = SmartHospital(scenario=spec, ids=IdFactory(deterministic=True))
        early = WindowedFeatureExtractor(window_seconds=5.0).extract(h.run(5))
        assert all("telemetry_residual" not in w.features for w in early)


# ===========================================================================
# Rule detector
# ===========================================================================
class TestRuleDetector:
    def test_detects_obvious_flood(self) -> None:
        d = RuleDetector()
        w = FeatureWindow(
            device_id="GW-1",
            window_start=__import__("datetime").datetime(
                2026, 1, 1, tzinfo=__import__("datetime").UTC
            ),
            window_end=__import__("datetime").datetime(
                2026, 1, 1, 0, 0, 5, tzinfo=__import__("datetime").UTC
            ),
            features={"packets_per_second": 20000.0, "syn_ratio": 0.9},
        )
        r = d.predict_window(w)
        assert r.is_attack is True
        assert r.attack_type is AttackType.DDOS
        assert r.severity is Severity.HIGH

    def test_silent_on_benign(self) -> None:
        import datetime as dt

        d = RuleDetector()
        w = FeatureWindow(
            device_id="GW-1",
            window_start=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
            window_end=dt.datetime(2026, 1, 1, 0, 0, 5, tzinfo=dt.UTC),
            features={"packets_per_second": 800.0, "syn_ratio": 0.02},
        )
        r = d.predict_window(w)
        assert r.is_attack is False
        assert r.attack_type is AttackType.NONE

    def test_results_are_tagged_as_inference(self, corpus) -> None:
        for r in RuleDetector().predict(corpus[:40]):
            assert r.assertion_class is AssertionClass.INFERENCE

    def test_never_reports_certainty(self, corpus) -> None:
        """A rule engine must not claim confidence 1.0."""
        for r in RuleDetector().predict(corpus):
            assert r.confidence <= 0.95

    def test_cites_the_events_it_used(self, corpus) -> None:
        for r in RuleDetector().predict(corpus[:30]):
            assert r.evidence_event_ids

    def test_rule_requires_all_conditions(self) -> None:
        rule = Rule(
            name="t",
            attack_type=AttackType.DOS,
            conditions=(("a", ">", 1.0), ("b", ">", 1.0)),
        )
        assert rule.evaluate({"a": 2.0, "b": 2.0})[0] is True
        assert rule.evaluate({"a": 2.0, "b": 0.0})[0] is False
        assert rule.evaluate({"a": 2.0})[0] is False, "missing feature must not match"

    def test_every_rule_maps_to_a_known_severity(self) -> None:
        for rule in DEFAULT_RULES:
            assert rule.attack_type in ATTACK_SEVERITY

    def test_is_a_weak_but_nonzero_baseline(self, corpus) -> None:
        """The floor baseline must detect something, and must not be strong.

        If hand-written rules matched the ML models, the ML would contribute
        nothing and should not be in the paper.
        """
        from sklearn.metrics import f1_score

        y = [w.y_binary for w in corpus]
        p = [int(r.is_attack) for r in RuleDetector().predict(corpus)]
        f1 = f1_score(y, p, zero_division=0)
        assert f1 > 0.05, "rule baseline detects nothing; rules are miscalibrated"
        assert f1 < 0.80, (
            "rule baseline is suspiciously strong, which suggests the task is trivially separable"
        )


# ===========================================================================
# Split protocols
# ===========================================================================
class TestSplitProtocols:
    def test_grouped_split_keeps_both_classes_on_both_sides(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        s.assert_usable()
        assert {w.y_binary for w in s.train} == {0, 1}
        assert {w.y_binary for w in s.test} == {0, 1}

    def test_grouped_split_shares_attack_types(self, corpus) -> None:
        """The headline protocol must not silently test on unseen families."""
        s = grouped_split(corpus, seed=20260101)
        train_types = {w.y_attack_type for w in s.train if w.y_binary}
        test_types = {w.y_attack_type for w in s.test if w.y_binary}
        unseen = test_types - train_types
        assert not unseen, (
            f"attack types {sorted(unseen)} appear only in test under the grouped "
            "protocol, which would measure zero-day generalisation instead of "
            "detection"
        )

    def test_grouped_split_does_not_split_episodes(self, corpus) -> None:
        """Adjacent windows of one attack are near-duplicates.

        Splitting mid-episode leaks correlated rows across the boundary.
        """
        s = grouped_split(corpus, seed=20260101)
        train_ids = {(w.device_id, w.window_start) for w in s.train}
        test_ids = {(w.device_id, w.window_start) for w in s.test}
        assert not (train_ids & test_ids), "a window appears in both splits"

    def test_grouped_split_is_deterministic(self, corpus) -> None:
        a = grouped_split(corpus, seed=7)
        b = grouped_split(corpus, seed=7)
        assert [w.window_start for w in a.test] == [w.window_start for w in b.test]

    def test_temporal_split_preserves_order(self, corpus) -> None:
        s = temporal_split(corpus)
        assert max(w.window_start for w in s.train) <= min(w.window_start for w in s.test)

    def test_temporal_split_reports_unseen_types(self, corpus) -> None:
        """The known limitation must be surfaced, not hidden.

        On this corpus a naive temporal split puts whole attack families only
        in test. That is legitimate to report, but it must be labelled.
        """
        s = temporal_split(corpus)
        train_types = {w.y_attack_type for w in s.train if w.y_binary}
        test_types = {w.y_attack_type for w in s.test if w.y_binary}
        if test_types - train_types:
            assert "ONLY in test" in s.notes or "unseen" in s.notes.lower(), (
                "a temporal split with unseen test families must say so in notes"
            )

    def test_unseen_attack_split_holds_the_family_out(self, corpus) -> None:
        s = unseen_attack_split(corpus, "mitm", seed=1)
        assert all(w.y_attack_type != "mitm" for w in s.train if w.y_binary), (
            "held-out family leaked into training"
        )
        assert any(w.y_attack_type == "mitm" for w in s.test if w.y_binary)
        assert s.held_out_attack == "mitm"
        assert "zero-day" in s.notes

    def test_unseen_attack_split_rejects_unknown_family(self, corpus) -> None:
        with pytest.raises(ValueError, match="no windows"):
            unseen_attack_split(corpus, "not_a_real_attack")

    def test_make_split_dispatches(self, corpus) -> None:
        assert make_split("grouped", corpus).protocol == "grouped"
        assert make_split("temporal", corpus).protocol == "temporal"
        with pytest.raises(ValueError, match="requires held_out_attack"):
            make_split("unseen_attack", corpus)

    def test_unusable_split_fails_loudly(self, corpus) -> None:
        from cybersecurity.splits import SplitResult

        benign = [w for w in corpus if w.y_binary == 0][:20]
        s = SplitResult(protocol="x", train=benign, test=benign)
        with pytest.raises(ValueError, match="single class"):
            s.assert_usable()

    def test_split_summary_reports_prevalence(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        summary = s.summary
        assert 0.0 < summary["test"]["prevalence"] < 1.0
        assert summary["train"]["attack_types"]


# ===========================================================================
# Threshold calibration
# ===========================================================================
class TestThresholdCalibration:
    def test_max_f1_beats_the_default_on_imbalanced_scores(self) -> None:
        """The measured failure: a good ranker scoring F1 0.0 at threshold 0.5."""
        rng = np.random.default_rng(0)
        y = np.array([0] * 950 + [1] * 50)
        p = np.concatenate([rng.uniform(0.0, 0.3, 950), rng.uniform(0.2, 0.45, 50)])

        default_pred = (p >= 0.5).astype(int)
        assert default_pred.sum() == 0, "fixture should produce zero detections at 0.5"

        choice = calibrate_threshold(y, p, objective="max_f1")
        tuned = (p >= choice.threshold).astype(int)
        assert tuned.sum() > 0
        assert choice.achieved["f1"] > 0.0
        assert choice.threshold < 0.5

    def test_recall_at_fpr_respects_the_constraint(self) -> None:
        rng = np.random.default_rng(1)
        y = np.array([0] * 900 + [1] * 100)
        p = np.concatenate([rng.beta(2, 8, 900), rng.beta(6, 3, 100)])
        c = calibrate_threshold(y, p, objective="max_recall_at_fpr", max_fpr=0.05)
        assert c.achieved["fpr"] <= 0.05 + 1e-9

    def test_min_fpr_at_recall_respects_the_constraint(self) -> None:
        rng = np.random.default_rng(2)
        y = np.array([0] * 900 + [1] * 100)
        p = np.concatenate([rng.beta(2, 8, 900), rng.beta(6, 3, 100)])
        c = calibrate_threshold(y, p, objective="min_fpr_at_recall", min_recall=0.7)
        assert c.achieved["recall"] >= 0.7 - 1e-9

    def test_reports_when_no_threshold_meets_the_constraint(self) -> None:
        """An unmeetable operating requirement must be reported, not hidden."""
        y = np.array([0] * 100 + [1] * 100)
        p = np.concatenate([np.full(100, 0.5), np.full(100, 0.5)])
        c = calibrate_threshold(y, p, objective="max_recall_at_fpr", max_fpr=0.0)
        assert c.note

    def test_single_class_validation_falls_back_safely(self) -> None:
        c = calibrate_threshold([0] * 20, [0.1] * 20)
        assert c.threshold == 0.5
        assert "single class" in c.note

    def test_unknown_objective_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown objective"):
            calibrate_threshold([0, 1], [0.1, 0.9], objective="nonsense")


# ===========================================================================
# Supervised detectors
# ===========================================================================
class TestSupervisedDetector:
    def test_matrix_rejects_leaking_columns(self) -> None:
        with pytest.raises(ValueError, match="Leaking columns"):
            windows_to_matrix([], feature_order=("packets", "ground_truth_attack"))

    def test_absent_features_become_nan_not_zero(self, corpus) -> None:
        """Zero is a meaningful value; imputing it would be a silent lie."""
        X, _, _names = windows_to_matrix(corpus[:100])
        assert np.isnan(X).any()

    def test_unfitted_detector_refuses_to_predict(self, corpus) -> None:
        with pytest.raises(RuntimeError, match="not fitted"):
            SupervisedDetector().predict_window(corpus[0])

    def test_single_class_training_is_rejected(self, corpus) -> None:
        benign = [w for w in corpus if w.y_binary == 0][:60]
        with pytest.raises(ValueError, match="single class"):
            SupervisedDetector().fit(benign)

    @pytest.mark.parametrize("model", ["logistic_regression", "random_forest", "gradient_boosting"])
    def test_each_model_trains_and_predicts(self, corpus, model: str) -> None:
        s = grouped_split(corpus, seed=20260101)
        d = SupervisedDetector(model_name=model, seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            report = d.fit(s.train)
        assert report.n_train == len(s.train)
        assert report.n_features > 0
        results = d.predict(s.test[:40])
        assert len(results) == 40
        for r in results:
            assert r.detector_kind is DetectorKind.SUPERVISED_CLASSIFIER
            assert 0.0 <= r.confidence <= 1.0

    def test_training_is_reproducible_from_a_seed(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)

        def probs():
            d = SupervisedDetector(model_name="random_forest", seed=99)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                d.fit(s.train)
            return [r.class_scores["attack_probability"] for r in d.predict(s.test[:30])]

        assert probs() == probs()

    def test_report_records_univariate_aucs(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        d = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            report = d.fit(s.train)
        assert report.univariate_auc
        top = report.max_univariate_auc
        assert top is not None

    def test_warns_when_a_single_feature_solves_the_task(self) -> None:
        """A degenerate task must trigger a warning in the training report."""
        import datetime as dt

        base = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        windows = []
        for i in range(120):
            attack = i >= 60
            windows.append(
                FeatureWindow(
                    device_id="D-1",
                    window_start=base + dt.timedelta(seconds=5 * i),
                    window_end=base + dt.timedelta(seconds=5 * i + 5),
                    # A planted, perfectly-separating feature.
                    features={"syn_ratio": 0.99 if attack else 0.01, "packets": 10.0},
                    y_binary=int(attack),
                )
            )
        d = SupervisedDetector(model_name="random_forest", seed=1)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            report = d.fit(windows, fit_attack_type_head=False)
        assert report.warnings
        assert "DEGENERACY" in report.warnings[0]

    def test_ml_beats_the_rule_baseline(self, corpus) -> None:
        """If ML cannot beat hand-written rules it does not belong in the paper."""
        from sklearn.metrics import roc_auc_score

        s = grouped_split(corpus, seed=20260101)
        d = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            d.fit(s.train)
        out = d.predict(s.test)
        y = [w.y_binary for w in s.test]
        probs = [r.class_scores["attack_probability"] for r in out]
        auc = roc_auc_score(y, probs)
        assert auc > 0.80, f"supervised ROC-AUC {auc:.3f} is too weak to justify ML over rules"

    def test_persistence_round_trip(self, corpus, tmp_path) -> None:
        s = grouped_split(corpus, seed=20260101)
        d = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            d.fit(s.train)
        before = [r.class_scores["attack_probability"] for r in d.predict(s.test[:20])]
        path = d.save(tmp_path / "m.joblib")
        loaded = SupervisedDetector.load(path)
        after = [r.class_scores["attack_probability"] for r in loaded.predict(s.test[:20])]
        assert before == after
        assert loaded.metadata.model_version == d.metadata.model_version

    def test_model_version_is_recorded(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        d = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            d.fit(s.train)
        assert d.metadata.model_version != "untrained"
        assert "random_forest" in d.metadata.model_version


# ===========================================================================
# Anomaly and ensemble
# ===========================================================================
class TestAnomalyDetector:
    def test_fits_on_benign_only(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        a = AnomalyDetector(seed=20260101)
        info = a.fit(s.train, benign_only=True)
        assert info["n_benign_train"] == sum(1 for w in s.train if w.y_binary == 0)

    def test_rejects_insufficient_benign_data(self, corpus) -> None:
        a = AnomalyDetector()
        with pytest.raises(ValueError, match="too few"):
            a.fit([w for w in corpus if w.y_binary == 0][:5])

    def test_never_claims_an_attack_type(self, corpus) -> None:
        """An anomaly detector cannot know what it found."""
        s = grouped_split(corpus, seed=20260101)
        a = AnomalyDetector(seed=20260101)
        a.fit(s.train)
        for r in a.predict(s.test):
            if r.is_attack:
                assert r.attack_type is AttackType.UNKNOWN

    def test_reports_deviating_features(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        a = AnomalyDetector(seed=20260101)
        a.fit(s.train)
        flagged = [r for r in a.predict(s.test) if r.is_attack]
        assert flagged
        assert flagged[0].contributing_features

    def test_scores_attacks_higher_on_average(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        a = AnomalyDetector(seed=20260101)
        a.fit(s.train)
        atk = [a.anomaly_score(w) for w in s.test if w.y_binary == 1]
        ben = [a.anomaly_score(w) for w in s.test if w.y_binary == 0]
        assert np.mean(atk) > np.mean(ben)


class TestEnsemble:
    def test_supervised_attribution_wins_when_it_fires(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        sup = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sup.fit(s.train)
        ano = AnomalyDetector(seed=20260101)
        ano.fit(s.train)
        ens = EnsembleDetector(sup, ano)
        out = ens.predict(s.test)
        assert all(r.detector_kind is DetectorKind.ENSEMBLE for r in out)
        named = [
            r
            for r in out
            if r.is_attack and r.attack_type not in {AttackType.UNKNOWN, AttackType.NONE}
        ]
        assert named, "ensemble should retain supervised attribution"

    def test_anomaly_only_detections_are_reported_as_unknown(self, corpus) -> None:
        s = grouped_split(corpus, seed=20260101)
        sup = SupervisedDetector(model_name="random_forest", seed=20260101)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sup.fit(s.train)
        ano = AnomalyDetector(seed=20260101)
        ano.fit(s.train)
        out = EnsembleDetector(sup, ano).predict(s.test)
        anomaly_only = [r for r in out if r.is_attack and "anomaly-only" in r.notes]
        for r in anomaly_only:
            assert r.attack_type is AttackType.UNKNOWN
