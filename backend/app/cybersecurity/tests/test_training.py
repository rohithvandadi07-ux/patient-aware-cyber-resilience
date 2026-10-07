import pytest

from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import load_real_dataset, train_baselines
from app.schemas.enums import AttackCategory


@pytest.fixture
def small_dataset():
    # Small, fast fixture for pipeline tests -- real metric *values* aren't
    # asserted here (this is synthetic data; the point is the pipeline runs
    # correctly end-to-end and produces well-formed output), but bounds and
    # shapes are.
    return generate_synthetic_dataset(
        seed=1,
        samples_per_class={
            AttackCategory.UNKNOWN: 60,
            AttackCategory.DOS: 40,
            AttackCategory.MQTT_BASED: 30,
            AttackCategory.SPOOFING: 20,
        },
    )


def test_train_baselines_produces_both_models(small_dataset):
    results = train_baselines(small_dataset, seed=1)
    assert set(results["models"].keys()) == {"random_forest", "xgboost"}


def test_metrics_are_well_formed_probabilities(small_dataset):
    results = train_baselines(small_dataset, seed=1)
    for model_result in results["models"].values():
        metrics = model_result["metrics"]
        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert 0.0 <= metrics["precision_macro"] <= 1.0
        assert 0.0 <= metrics["recall_macro"] <= 1.0
        assert 0.0 <= metrics["f1_macro"] <= 1.0
        for fpr in metrics["false_positive_rate_per_class"].values():
            assert 0.0 <= fpr <= 1.0


def test_class_weights_are_higher_for_rarer_classes(small_dataset):
    results = train_baselines(small_dataset, seed=1)
    weights = results["class_weights"]
    # spoofing (20 samples) is rarer than unknown (60 samples), so balanced
    # class weighting must give it a higher weight.
    assert weights["spoofing"] > weights["unknown"]


def test_same_seed_is_reproducible(small_dataset):
    results1 = train_baselines(small_dataset, seed=1)
    results2 = train_baselines(small_dataset, seed=1)
    rf1 = results1["models"]["random_forest"]["metrics"]["accuracy"]
    rf2 = results2["models"]["random_forest"]["metrics"]["accuracy"]
    assert rf1 == rf2


def test_load_real_dataset_raises_not_implemented(tmp_path):
    with pytest.raises(NotImplementedError, match="not implemented"):
        load_real_dataset(tmp_path)


def test_compute_metrics_confusion_matrix_shape(small_dataset):
    results = train_baselines(small_dataset, seed=1)
    metrics = results["models"]["random_forest"]["metrics"]
    labels = metrics["confusion_matrix_labels"]
    cm = metrics["confusion_matrix"]
    assert len(cm) == len(labels)
    assert all(len(row) == len(labels) for row in cm)
