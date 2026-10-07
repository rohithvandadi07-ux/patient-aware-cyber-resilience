from app.cybersecurity.synthetic_data import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    generate_synthetic_dataset,
)


def test_generated_dataset_has_expected_columns():
    df = generate_synthetic_dataset(seed=1, samples_per_class=None)
    for column in FEATURE_COLUMNS:
        assert column in df.columns
    assert LABEL_COLUMN in df.columns


def test_same_seed_produces_identical_dataset():
    df1 = generate_synthetic_dataset(seed=7)
    df2 = generate_synthetic_dataset(seed=7)
    assert df1.equals(df2)


def test_different_seed_produces_different_dataset():
    df1 = generate_synthetic_dataset(seed=1)
    df2 = generate_synthetic_dataset(seed=2)
    assert not df1.equals(df2)


def test_class_imbalance_matches_requested_sizes():
    from app.schemas.enums import AttackCategory

    sizes = {
        AttackCategory.UNKNOWN: 100,
        AttackCategory.DOS: 10,
        AttackCategory.SPOOFING: 5,
    }
    df = generate_synthetic_dataset(seed=1, samples_per_class=sizes)
    counts = df[LABEL_COLUMN].value_counts()
    assert counts["unknown"] == 100
    assert counts["dos"] == 10
    assert counts["spoofing"] == 5


def test_all_feature_values_are_non_negative():
    df = generate_synthetic_dataset(seed=3)
    assert (df[FEATURE_COLUMNS] >= 0).all().all()
