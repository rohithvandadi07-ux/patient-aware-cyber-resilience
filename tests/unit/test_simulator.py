"""IoMT simulator tests.

The determinism tests are load-bearing for the whole research framework:
if the simulator is not reproducible, no experiment in this repository is.
"""

from __future__ import annotations

import pytest

from backend.app.domain.enums import (
    AttackType,
    DeviceOperationalState,
    EventKind,
    NetworkState,
)
from backend.app.domain.ids import IdFactory
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import (
    MANDATED_SCENARIOS,
    SCENARIOS,
    get_scenario,
    standard_fleet,
)
from iomt_simulator.scenarios.spec import ScenarioSpec

pytestmark = pytest.mark.unit


def _signature(events) -> list[tuple]:
    return [
        (e.event_id, e.kind.value, e.device_id, tuple(sorted(e.measurements.items())))
        for e in events
    ]


class TestDeterminism:
    def test_identical_runs_produce_identical_streams(self) -> None:
        a = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        b = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        assert _signature(a.run(80)) == _signature(b.run(80))

    def test_different_seeds_produce_different_streams(self) -> None:
        s1 = get_scenario("baseline_normal")
        s2 = s1.model_copy(update={"seed": s1.seed + 1})
        a = SmartHospital(scenario=s1, ids=IdFactory(deterministic=True))
        b = SmartHospital(scenario=s2, ids=IdFactory(deterministic=True))
        assert _signature(a.run(60)) != _signature(b.run(60))

    def test_incremental_and_bulk_runs_agree(self) -> None:
        a = SmartHospital(scenario=get_scenario("mitm_monitor"), ids=IdFactory(deterministic=True))
        b = SmartHospital(scenario=get_scenario("mitm_monitor"), ids=IdFactory(deterministic=True))
        bulk = a.run(50)
        incremental = []
        for _ in range(50):
            incremental.extend(b.tick())
        assert _signature(bulk) == _signature(incremental)

    def test_device_stream_independent_of_fleet_order(self) -> None:
        """Reordering the fleet must not perturb any device's own stream."""
        base = get_scenario("baseline_normal")
        reversed_fleet = base.model_copy(update={"devices": list(reversed(base.devices))})
        a = SmartHospital(scenario=base, ids=IdFactory(deterministic=True))
        b = SmartHospital(scenario=reversed_fleet, ids=IdFactory(deterministic=True))
        a.run(40)
        b.run(40)
        va = [
            tuple(sorted(e.measurements.items()))
            for e in a.event_log
            if e.device_id == "VENT-ICU-01" and e.kind is EventKind.TELEMETRY
        ]
        vb = [
            tuple(sorted(e.measurements.items()))
            for e in b.event_log
            if e.device_id == "VENT-ICU-01" and e.kind is EventKind.TELEMETRY
        ]
        assert va == vb


class TestBaseline:
    def test_no_attack_labels_in_clean_baseline(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=120)
        assert not any(e.ground_truth_is_attack for e in h.event_log)

    def test_all_devices_remain_healthy(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=180)
        for d in h.devices.values():
            assert d.state.operational_state in {
                DeviceOperationalState.ACTIVE,
                DeviceOperationalState.STANDBY,
            }, f"{d.profile.device_id} degraded without any attack"

    def test_ventilated_patient_stays_oxygenated(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=240)
        assert h.devices["VENT-ICU-01"].spo2 > 94.0

    def test_telemetry_and_flows_are_emitted(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=30)
        kinds = {e.kind for e in h.event_log}
        assert EventKind.TELEMETRY in kinds
        assert EventKind.NETWORK_FLOW in kinds


class TestScenarioLibrary:
    @pytest.mark.parametrize("name", sorted(SCENARIOS))
    def test_every_scenario_runs(self, name: str) -> None:
        h = SmartHospital(scenario=get_scenario(name), ids=IdFactory(deterministic=True))
        events = h.run(min(60, get_scenario(name).total_ticks))
        assert events, f"scenario {name} produced no events"

    @pytest.mark.parametrize("name", MANDATED_SCENARIOS)
    def test_mandated_scenarios_declare_expectations(self, name: str) -> None:
        assert get_scenario(name).expectations, "mandated scenario must declare expectations"

    def test_yaml_roundtrip_preserves_scenario(self, tmp_path) -> None:
        original = get_scenario("s2_ventilator_compromise")
        path = tmp_path / "s.yaml"
        original.to_yaml(path)
        reloaded = ScenarioSpec.from_yaml(path)
        assert reloaded.seed == original.seed
        assert len(reloaded.attack_specs) == len(original.attack_specs)
        a = SmartHospital(scenario=original, ids=IdFactory(deterministic=True))
        b = SmartHospital(scenario=reloaded, ids=IdFactory(deterministic=True))
        assert _signature(a.run(40)) == _signature(b.run(40))

    def test_fleet_has_both_critical_and_noncritical_assets(self) -> None:
        tiers = {d.criticality.value for d in standard_fleet()}
        assert "life_sustaining" in tiers
        assert "non_clinical" in tiers, "policy engine needs low-criticality targets"


class TestVentilatorClinicalCoupling:
    """The ventilator is where the central research claim must hold."""

    def test_reduced_support_causes_desaturation(self) -> None:
        h = SmartHospital(
            scenario=get_scenario("s2_ventilator_compromise"), ids=IdFactory(deterministic=True)
        )
        h.run(55)
        before = h.devices["VENT-ICU-01"].spo2
        h.run_until(160)
        after = h.devices["VENT-ICU-01"].spo2
        assert after < before - 8.0, "attack must produce measurable clinical deterioration"

    def test_desaturation_crosses_critical_threshold(self) -> None:
        h = SmartHospital(
            scenario=get_scenario("s2_ventilator_compromise"), ids=IdFactory(deterministic=True)
        )
        h.run(140)
        v = h.devices["VENT-ICU-01"]
        assert v.spo2 < v.SPO2_CRITICAL
        assert v.state.operational_state is DeviceOperationalState.FAULT
        assert "PATIENT_AT_RISK" in v.state.fault_codes

    def test_desaturation_is_gradual_not_instantaneous(self) -> None:
        """Clinically plausible rate: must not collapse within a few ticks."""
        h = SmartHospital(
            scenario=get_scenario("s2_ventilator_compromise"), ids=IdFactory(deterministic=True)
        )
        h.run(70)
        assert h.devices["VENT-ICU-01"].spo2 > 92.0, "desaturation unrealistically fast"

    def test_telemetry_spoofing_hides_deterioration(self) -> None:
        """The reported signal looks healthy while the truth deteriorates.

        This deception is precisely why evidence-based investigation and
        patient-aware reasoning are required rather than trusting telemetry.
        """
        h = SmartHospital(
            scenario=get_scenario("s2_ventilator_compromise"), ids=IdFactory(deterministic=True)
        )
        h.run(150)
        tel = [
            e for e in h.event_log if e.device_id == "VENT-ICU-01" and e.kind is EventKind.TELEMETRY
        ][-1]
        reported = tel.measurements["spo2_pct"]
        truth = tel.measurements["truth_spo2_pct"]
        assert reported > 94.0, "spoofed telemetry should look healthy"
        assert truth < 88.0, "ground truth should show deterioration"
        assert reported - truth > 5.0

    def test_shutdown_stops_therapy_and_worsens_patient(self) -> None:
        """The counterfactual: the 'secure' action is clinically harmful."""
        h = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        h.run(40)
        v = h.devices["VENT-ICU-01"]
        assert v.spo2 > 95.0
        h.apply_response("shutdown_device", device_id="VENT-ICU-01")
        h.run(90)
        assert v.ventilating is False
        assert v.spo2 < 94.0, "shutting down a life-sustaining device must harm the patient"

    def test_failover_protects_patient_where_redundancy_exists(self) -> None:
        """Redundancy is what makes a high-impact action clinically safe."""
        h = SmartHospital(
            scenario=get_scenario("baseline_normal"), ids=IdFactory(deterministic=True)
        )
        h.run(40)
        h.apply_response("failover_to_redundant_device", device_id="VENT-ICU-02")
        h.run(120)
        v2 = h.devices["VENT-ICU-02"]
        assert v2.profile.has_redundant_peer is True
        assert v2.spo2 > 92.0, "safe failover must not desaturate the patient"


class TestAttackObservability:
    def test_ddos_inflates_flow_rates(self, make_hospital) -> None:
        h = make_hospital("network_flood_icu", ticks=90)
        attack_flows = [
            e
            for e in h.event_log
            if e.kind is EventKind.NETWORK_FLOW and e.ground_truth_attack is AttackType.DDOS
        ]
        assert attack_flows
        assert max(e.measurements["packets_per_second"] for e in attack_flows) > 1000.0

    def test_port_scan_raises_distinct_destination_ports(self, make_hospital) -> None:
        h = make_hospital("recon_then_pivot", ticks=50)
        scans = [e for e in h.event_log if e.ground_truth_attack is AttackType.PORT_SCAN]
        assert scans
        assert max(e.measurements["distinct_dst_ports"] for e in scans) > 20.0

    def test_arp_spoofing_shows_duplicate_mac(self, make_hospital) -> None:
        h = make_hospital("mitm_monitor", ticks=80)
        arp = [e for e in h.event_log if e.ground_truth_attack is AttackType.ARP_SPOOFING]
        assert arp
        assert any(e.measurements["duplicate_mac_observed"] == 1.0 for e in arp)

    def test_ransomware_shows_host_signature(self, make_hospital) -> None:
        h = make_hospital("s1_noncritical_compromise", ticks=130)
        ws = h.devices["WS-NURSE-01"]
        assert ws.encrypted_file_ops > 100.0
        assert ws.cpu_pct > 70.0
        assert ws.state.alarm_active is True

    def test_malicious_command_arrives_unauthenticated(self, make_hospital) -> None:
        h = make_hospital("s3_recovery_failure", ticks=70)
        cmds = [
            e
            for e in h.event_log
            if e.kind is EventKind.DEVICE_COMMAND and e.device_id == "PUMP-ICU-01"
        ]
        assert cmds
        assert any(e.measurements["authenticated_session"] == 0.0 for e in cmds)

    def test_counters_stay_in_realistic_ranges(self, make_hospital) -> None:
        """Guards against unbounded accumulation in long runs."""
        h = make_hospital("s1_noncritical_compromise", ticks=240)
        ws = h.devices["WS-NURSE-01"]
        assert ws.cpu_pct <= 100.0
        assert ws.disk_write_mb_s <= 500.0
        assert ws.encrypted_file_ops <= 3000.0


class TestActuation:
    def test_quarantine_segments_the_device(self, make_hospital) -> None:
        h = make_hospital("s1_noncritical_compromise", ticks=50)
        h.apply_response("quarantine_device", device_id="WS-NURSE-01")
        st = h.devices["WS-NURSE-01"].state
        assert st.network_state is NetworkState.SEGMENTED
        assert st.operational_state is DeviceOperationalState.QUARANTINED

    def test_isolation_silences_network_flows(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=30)
        h.apply_response("isolate_network_segment", segment="vlan-admin")
        before = len(h.event_log)
        h.run(10)
        flows = [
            e
            for e in h.event_log[before:]
            if e.kind is EventKind.NETWORK_FLOW and e.device_id == "WS-NURSE-01"
        ]
        assert flows == [], "isolated device must emit no flows"

    def test_credential_rotation_stops_command_injection(self, make_hospital) -> None:
        h = make_hospital("s3_recovery_failure", ticks=80)
        pump = h.devices["PUMP-ICU-01"]
        assert any(a.attack_type is AttackType.MALICIOUS_COMMAND for a in pump.attacks)
        h.apply_response("rotate_credentials", device_id="PUMP-ICU-01")
        assert not any(a.attack_type is AttackType.MALICIOUS_COMMAND for a in pump.attacks)
        assert pump.state.credentials_version == 2

    def test_traffic_blocking_does_not_stop_a_session_based_attack(self, make_hospital) -> None:
        """This asymmetry is what makes mandated scenario 3 fail recovery."""
        h = make_hospital("s3_recovery_failure", ticks=80)
        pump = h.devices["PUMP-ICU-01"]
        h.apply_response("block_source_traffic", device_id="PUMP-ICU-01")
        assert any(a.attack_type is AttackType.MALICIOUS_COMMAND for a in pump.attacks), (
            "traffic blocking must not clear a valid-session attack"
        )

    def test_control_release_restores_connectivity(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=20)
        h.apply_response("quarantine_device", device_id="PUMP-WARD-02")
        assert h.devices["PUMP-WARD-02"].state.network_state is NetworkState.SEGMENTED
        h.release_response("quarantine_device", "PUMP-WARD-02")
        assert h.devices["PUMP-WARD-02"].state.network_state is NetworkState.NORMAL

    def test_response_reports_affected_devices(self, make_hospital) -> None:
        h = make_hospital("baseline_normal", ticks=10)
        result = h.apply_response("isolate_network_segment", segment="vlan-clinical")
        assert result["succeeded"] is True
        assert len(result["affected_devices"]) >= 5
