from fastapi.testclient import TestClient

from app.iomt_simulator.patients import build_default_patients, news2
from app.main import app
from app.schemas.patient import AcuityBand, Consciousness, Vitals


def _vitals(**overrides) -> Vitals:
    base = dict(
        respiration_rate=16, spo2=97, on_supplemental_oxygen=False, systolic_bp=124,
        pulse=78, consciousness=Consciousness.ALERT, temperature_c=36.8,
    )
    base.update(overrides)
    return Vitals(**base)


def test_normal_vitals_score_zero_low():
    score, _, red_flag, band = news2(_vitals())
    assert (score, red_flag, band) == (0, False, AcuityBand.LOW)


def test_single_red_flag_is_medium_even_with_low_total():
    score, _, red_flag, band = news2(_vitals(respiration_rate=8))
    assert score == 3 and red_flag and band == AcuityBand.MEDIUM


def test_total_five_is_medium_and_seven_is_high():
    five = _vitals(respiration_rate=22, spo2=93, pulse=100)  # 2 + 2 + 1
    assert news2(five)[0] == 5 and news2(five)[3] == AcuityBand.MEDIUM
    seven = _vitals(respiration_rate=22, spo2=93, pulse=100, on_supplemental_oxygen=True)
    assert news2(seven)[0] == 7 and news2(seven)[3] == AcuityBand.HIGH


def test_maximum_score_is_nineteen_with_these_values_and_high():
    worst = _vitals(
        respiration_rate=25, spo2=91, on_supplemental_oxygen=True, systolic_bp=90,
        pulse=131, consciousness=Consciousness.CVPU, temperature_c=39.1,
    )
    score, _, _, band = news2(worst)
    assert score == 19 and band == AcuityBand.HIGH


def test_vitals_are_deterministic_and_patient_two_deteriorates():
    reg = build_default_patients()
    first = reg.get_patient_state("synthetic-patient-002")
    again = reg.get_patient_state("synthetic-patient-002")
    assert first == again
    assert first.news2_score == 0 and first.acuity_band == AcuityBand.LOW
    reg.advance(180)
    later = reg.get_patient_state("synthetic-patient-002")
    assert later.news2_score >= 5 and later.acuity_band in {AcuityBand.MEDIUM, AcuityBand.HIGH}


def test_ventilated_patient_is_always_high_and_maps_to_its_device():
    reg = build_default_patients()
    state = reg.for_device("ventilator-01")
    assert state is not None and state.acuity_band == AcuityBand.HIGH
    assert reg.for_device("infusion-pump-01") is None


def test_patients_api_lists_and_404s():
    client = TestClient(app)
    response = client.get("/patients")
    assert response.status_code == 200
    assert {p["patient_id"] for p in response.json()} == {
        "synthetic-patient-001",
        "synthetic-patient-002",
    }
    assert client.get("/patients/nope").status_code == 404