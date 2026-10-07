from datetime import UTC, datetime, timedelta

import pytest

from app.cybersecurity.detection_service import (
    DetectionService,
    ModelNotLoadedError,
    load_model,
)
from app.cybersecurity.feature_extraction import FeatureWindow
from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import save_artifacts, train_baselines
from app.schemas.detection import DetectionEvent
from app.schemas.enums import AttackCategory
from app.schemas.events import NetworkEvent

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def trained_model_dir(tmp_path_factory):
    # Train once per test module (slow-ish: two real model fits) and reuse --
    # these tests exercise the loading/scoring/thresholding logic, not
    # training itself (that's test_training.py's job).
    output_dir = tmp_path_factory.mktemp("models")
    df = generate_synthetic_dataset(seed=5)
    results = train_baselines(df, seed=5)
    save_artifacts(results, output_dir, data_source="synthetic (test fixture)", seed=5)
    return output_dir


@pytest.fixture(scope="module")
def rf_model(trained_model_dir):
    return load_model(trained_model_dir / "random_forest.joblib")


def _burst_window(device_id: str = "ventilator-01", count: int = 400) -> FeatureWindow:
    events = [
        NetworkEvent(
            device_id=device_id,
            timestamp=_NOW + timedelta(milliseconds=i * 2),
            event_type="connection_attempt_syn",
            source=f"10.0.0.{i % 5}",
            payload={"protocol": "tcp"},
            is_attack_injection=True,
        )
        for i in range(count)
    ]
    return FeatureWindow(
        device_id=device_id, window_start=_NOW, window_end=_NOW + timedelta(seconds=1), events=events
    )


def test_load_model_raises_file_not_found_for_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError, match="Train one first"):
        load_model(tmp_path / "does_not_exist.joblib")


def test_load_model_raises_for_missing_metadata(tmp_path):
    # An artifact file with no paired metadata is a malformed/hand-placed
    # artifact, not a normal "not trained yet" case -- distinct error message.
    fake_artifact = tmp_path / "random_forest.joblib"
    fake_artifact.write_bytes(b"not a real joblib file")
    with pytest.raises(FileNotFoundError, match="metadata"):
        load_model(fake_artifact)


def test_load_model_reads_labels_from_metadata(rf_model):
    assert set(rf_model.labels) == {"ddos", "dos", "mqtt_based", "reconnaissance", "spoofing", "unknown"}
    assert rf_model.model_name == "random_forest"


def test_score_window_returns_detection_event_or_none(rf_model):
    service = DetectionService(rf_model, confidence_threshold=0.0)
    result = service.score_window(_burst_window())
    # With threshold 0.0, only an actual "unknown" (benign) prediction suppresses.
    assert result is None or isinstance(result, DetectionEvent)


def test_score_window_suppresses_below_confidence_threshold(rf_model):
    # A threshold of 1.01 can never be cleared by any real probability.
    service = DetectionService(rf_model, confidence_threshold=1.01)
    result = service.score_window(_burst_window())
    assert result is None


def test_score_window_never_emits_unknown_label(rf_model):
    # AttackCategory.UNKNOWN doubles as "benign" -- the contract is that a
    # benign prediction never produces a DetectionEvent, however confident.
    service = DetectionService(rf_model, confidence_threshold=0.0)
    # Run across a spread of windows; if any happens to predict "unknown",
    # score_window must return None for it rather than an event with
    # attack_type=UNKNOWN.
    for count in (0, 1, 5, 50, 400):
        result = service.score_window(_burst_window(count=count))
        if result is not None:
            assert result.attack_type != AttackCategory.UNKNOWN


def test_score_window_sets_device_id_and_timestamp_from_window(rf_model):
    service = DetectionService(rf_model, confidence_threshold=0.0)
    window = _burst_window(device_id="infusion-pump-01")
    result = service.score_window(window)
    if result is not None:
        assert result.device_id == "infusion-pump-01"
        assert result.timestamp == window.window_end


def test_score_window_evidence_ref_is_bounded_length_regardless_of_event_count(rf_model):
    service = DetectionService(rf_model, confidence_threshold=0.0)
    result = service.score_window(_burst_window(count=400))
    if result is not None:
        # Must never scale linearly with event count (that would mean raw
        # evidence leaked into the reference instead of a bounded summary).
        assert len(result.evidence_ref) < 300


def test_detection_service_requires_predict_proba():
    class _FakeModel:
        def __init__(self):
            self.estimator = object()  # no predict_proba
            self.labels = ["unknown"]
            self.model_name = "fake"
            self.source_path = None

    service = DetectionService(_FakeModel())
    window = _burst_window()
    with pytest.raises(ModelNotLoadedError):
        service.score_window(window)
