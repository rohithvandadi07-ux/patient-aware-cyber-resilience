"""Built-in scenario library.

Defines the standard ICU fleet and the research scenarios the platform is
evaluated on, including the three mandated deterministic scenarios:

S1  Non-critical asset compromised      -> autonomous containment defensible
S2  Ventilator compromised, patient
    life-critically dependent           -> unsafe shutdown denied, approval required
S3  Response executed, recovery fails   -> re-investigation and re-planning

Scenarios are data. ``export_all`` writes them to ``configs/scenarios/`` so
that every experiment cites a file, not a function.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from backend.app.domain.enums import (
    AcuityLevel,
    AttackType,
    CriticalityTier,
    DeviceType,
    PatientDependencyLevel,
)
from iomt_simulator.scenarios.spec import AttackSpec, DeviceSpec, PatientSpec, ScenarioSpec

START = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Standard ICU fleet
# ---------------------------------------------------------------------------
def standard_fleet() -> list[DeviceSpec]:
    """The reference fleet used by every scenario.

    Criticality assignments reflect the device's clinical role, and are the
    input the clinical-risk term reads. They are simulation parameters, not
    clinical guidance.
    """
    return [
        # --- ventilator: the safety-critical anchor --------------------
        DeviceSpec(
            device_id="VENT-ICU-01",
            device_type=DeviceType.VENTILATOR,
            model_name="SimVent-900",
            ward="ICU-1",
            criticality=CriticalityTier.LIFE_SUSTAINING,
            life_support_relevant=True,
            has_redundant_peer=False,
            supports_safe_failover=False,
            acceptable_interruption_seconds=0.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.11",
            mac_address="02:1a:11:00:00:11",
            firmware_version="4.2.1",
            patient=PatientSpec(
                patient_ref="SYN-PT-0001",
                acuity=AcuityLevel.CRITICAL,
                dependency=PatientDependencyLevel.LIFE_CRITICAL,
                on_life_support=True,
                clinician_present=True,
                tolerable_interruption_minutes=0.0,
            ),
        ),
        # --- ventilator with a redundant peer: failover is viable ------
        DeviceSpec(
            device_id="VENT-ICU-02",
            device_type=DeviceType.VENTILATOR,
            model_name="SimVent-900",
            ward="ICU-1",
            criticality=CriticalityTier.LIFE_SUSTAINING,
            life_support_relevant=True,
            has_redundant_peer=True,
            redundant_peer_id="VENT-ICU-03",
            supports_safe_failover=True,
            acceptable_interruption_seconds=15.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.12",
            mac_address="02:1a:11:00:00:12",
            firmware_version="4.2.1",
            patient=PatientSpec(
                patient_ref="SYN-PT-0002",
                acuity=AcuityLevel.SERIOUS,
                dependency=PatientDependencyLevel.LIFE_CRITICAL,
                on_life_support=True,
                clinician_present=True,
                tolerable_interruption_minutes=0.5,
            ),
        ),
        DeviceSpec(
            device_id="VENT-ICU-03",
            device_type=DeviceType.VENTILATOR,
            model_name="SimVent-900",
            ward="ICU-1",
            criticality=CriticalityTier.LIFE_SUSTAINING,
            life_support_relevant=True,
            has_redundant_peer=True,
            redundant_peer_id="VENT-ICU-02",
            supports_safe_failover=True,
            acceptable_interruption_seconds=15.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.13",
            mac_address="02:1a:11:00:00:13",
            firmware_version="4.2.1",
        ),
        # --- infusion pumps -------------------------------------------
        DeviceSpec(
            device_id="PUMP-ICU-01",
            device_type=DeviceType.INFUSION_PUMP,
            model_name="SimPump-ML",
            ward="ICU-1",
            criticality=CriticalityTier.LIFE_SUPPORTING,
            life_support_relevant=True,
            acceptable_interruption_seconds=60.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.21",
            mac_address="02:1a:11:00:00:21",
            firmware_version="2.7.0",
            patient=PatientSpec(
                patient_ref="SYN-PT-0003",
                acuity=AcuityLevel.SERIOUS,
                dependency=PatientDependencyLevel.CONTINUOUS,
                on_life_support=False,
                clinician_present=True,
                tolerable_interruption_minutes=2.0,
            ),
        ),
        DeviceSpec(
            device_id="PUMP-WARD-02",
            device_type=DeviceType.INFUSION_PUMP,
            model_name="SimPump-ML",
            ward="WARD-3",
            criticality=CriticalityTier.CLINICALLY_SIGNIFICANT,
            life_support_relevant=False,
            acceptable_interruption_seconds=600.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.22",
            mac_address="02:1a:11:00:00:22",
            firmware_version="2.7.0",
            patient=PatientSpec(
                patient_ref="SYN-PT-0004",
                acuity=AcuityLevel.STABLE,
                dependency=PatientDependencyLevel.INTERMITTENT,
                on_life_support=False,
                clinician_present=True,
                tolerable_interruption_minutes=30.0,
            ),
        ),
        # --- monitors -------------------------------------------------
        DeviceSpec(
            device_id="ECG-ICU-01",
            device_type=DeviceType.ECG_MONITOR,
            model_name="SimMonitor-5",
            ward="ICU-1",
            criticality=CriticalityTier.CLINICALLY_SIGNIFICANT,
            life_support_relevant=False,
            acceptable_interruption_seconds=120.0,
            network_segment="vlan-clinical",
            ip_address="10.0.1.31",
            mac_address="02:1a:11:00:00:31",
            firmware_version="3.1.4",
            patient=PatientSpec(
                patient_ref="SYN-PT-0001",
                acuity=AcuityLevel.CRITICAL,
                dependency=PatientDependencyLevel.CONTINUOUS,
                on_life_support=False,
                clinician_present=True,
                tolerable_interruption_minutes=5.0,
            ),
        ),
        # --- non-clinical assets: autonomy is defensible here ----------
        DeviceSpec(
            device_id="WS-NURSE-01",
            device_type=DeviceType.WORKSTATION,
            model_name="SimWorkstation",
            ward="ICU-1",
            criticality=CriticalityTier.NON_CLINICAL,
            life_support_relevant=False,
            acceptable_interruption_seconds=3600.0,
            network_segment="vlan-admin",
            ip_address="10.0.10.44",
            mac_address="02:1a:11:00:00:44",
            firmware_version="win-11-23h2",
        ),
        DeviceSpec(
            device_id="GW-ICU-01",
            device_type=DeviceType.NETWORK_GATEWAY,
            model_name="SimGateway",
            ward="ICU-1",
            criticality=CriticalityTier.SUPPORTIVE,
            life_support_relevant=False,
            acceptable_interruption_seconds=90.0,
            network_segment="vlan-infra",
            ip_address="10.0.0.1",
            mac_address="02:1a:11:00:00:01",
            firmware_version="1.9.2",
        ),
    ]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
def baseline_normal() -> ScenarioSpec:
    """Attack-free baseline. Establishes normal behaviour and FPR."""
    return ScenarioSpec(
        scenario_id="baseline_normal",
        description=(
            "Attack-free operation of the standard ICU fleet. Used to establish "
            "normal-behaviour baselines and to measure the false-positive rate."
        ),
        seed=20260101,
        total_ticks=600,
        start_time=START,
        devices=standard_fleet(),
        attacks=[],
        expectations={"incidents_expected": 0, "purpose": "false_positive_rate"},
    )


def s1_noncritical_compromise() -> ScenarioSpec:
    """SCENARIO 1 (mandated): non-critical asset compromised."""
    return ScenarioSpec(
        scenario_id="s1_noncritical_compromise",
        description=(
            "MANDATED SCENARIO 1. A nurse-station workstation (NON_CLINICAL "
            "criticality, no patient dependency) is compromised via credential "
            "brute force followed by ransomware-like behaviour. Because no "
            "patient depends on this asset, clinical risk is low and the policy "
            "engine should permit autonomous containment without human approval."
        ),
        seed=20260102,
        total_ticks=240,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
                target_device_id="WS-NURSE-01",
                start_tick=40,
                duration_ticks=30,
                intensity=1.0,
                source_ip="203.0.113.77",
                label="initial access",
            ),
            AttackSpec(
                attack_type=AttackType.RANSOMWARE_BEHAVIOUR,
                target_device_id="WS-NURSE-01",
                start_tick=72,
                duration_ticks=100,
                intensity=1.0,
                source_ip="203.0.113.77",
                label="impact",
            ),
        ],
        expectations={
            "expected_policy_decision": "auto_allowed",
            "expected_clinical_risk_band": ["negligible", "low"],
            "forbidden_actions": [],
            "autonomous_containment_permitted": True,
        },
    )


def s2_ventilator_compromise() -> ScenarioSpec:
    """SCENARIO 2 (mandated): ventilator with life-critical dependency."""
    return ScenarioSpec(
        scenario_id="s2_ventilator_compromise",
        description=(
            "MANDATED SCENARIO 2. VENT-ICU-01 (LIFE_SUSTAINING, patient "
            "life-critically dependent, no redundant peer, zero tolerable "
            "interruption) is compromised by a malicious command that reduces "
            "respiratory support, with concurrent telemetry spoofing hiding the "
            "deterioration. Expected: clinical risk SEVERE; SHUTDOWN_DEVICE and "
            "network ISOLATION denied as unsafe; any high-impact action requires "
            "human approval. This is the scenario where the most secure response "
            "is NOT the safest clinical response."
        ),
        seed=20260103,
        total_ticks=300,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.ARP_SPOOFING,
                target_device_id="VENT-ICU-01",
                start_tick=30,
                duration_ticks=40,
                intensity=1.0,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
                label="position for MITM from compromised workstation",
            ),
            AttackSpec(
                attack_type=AttackType.MALICIOUS_COMMAND,
                target_device_id="VENT-ICU-01",
                start_tick=60,
                duration_ticks=160,
                intensity=1.0,
                source_ip="10.0.10.44",
                params={"target_rr": 5.0, "target_tidal_ml": 180.0},
                label="reduce respiratory support",
            ),
            AttackSpec(
                attack_type=AttackType.SPOOFED_TELEMETRY,
                target_device_id="VENT-ICU-01",
                start_tick=60,
                duration_ticks=160,
                intensity=1.0,
                source_ip="10.0.10.44",
                label="mask deterioration from clinicians",
            ),
        ],
        expectations={
            "expected_clinical_risk_band": ["high", "severe"],
            "forbidden_actions": ["shutdown_device", "isolate_network_segment"],
            "approval_required_for_high_impact": True,
            "autonomous_containment_permitted": False,
        },
    )


def s3_recovery_failure() -> ScenarioSpec:
    """SCENARIO 3 (mandated): recovery fails, forcing re-planning."""
    return ScenarioSpec(
        scenario_id="s3_recovery_failure",
        description=(
            "MANDATED SCENARIO 3. PUMP-ICU-01 is attacked by a persistent "
            "malicious-command channel that survives the first containment "
            "attempt (traffic blocking does not revoke the attacker's valid "
            "session). Recovery verification must therefore FAIL, residual risk "
            "must remain elevated, and the loop must re-investigate and select a "
            "DIFFERENT action (credential rotation) rather than blindly repeating "
            "the first one."
        ),
        seed=20260104,
        total_ticks=360,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.UNAUTHORIZED_ACCESS,
                target_device_id="PUMP-ICU-01",
                start_tick=45,
                duration_ticks=None,
                intensity=1.0,
                source_ip="10.0.10.44",
                label="persistent session, survives traffic blocking",
            ),
            AttackSpec(
                attack_type=AttackType.MALICIOUS_COMMAND,
                target_device_id="PUMP-ICU-01",
                start_tick=50,
                duration_ticks=None,
                intensity=1.0,
                source_ip="10.0.10.44",
                params={"target_rate_ml_h": 110.0},
                label="persistent over-infusion",
            ),
        ],
        expectations={
            "first_recovery_outcome": ["residual_risk", "failed"],
            "requires_reinvestigation": True,
            "must_not_repeat_same_action": True,
            "expected_final_action_class": "credential_or_session_revocation",
        },
    )


def network_flood_icu() -> ScenarioSpec:
    """DDoS against the ICU gateway: high cyber risk, diffuse clinical risk."""
    return ScenarioSpec(
        scenario_id="network_flood_icu",
        description=(
            "Volumetric DDoS against the ICU network gateway. Cyber risk is high "
            "and the correct response (upstream traffic blocking) is clinically "
            "cheap, so this scenario tests that patient-awareness does not make "
            "the system needlessly timid."
        ),
        seed=20260105,
        total_ticks=240,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.DDOS,
                target_device_id="GW-ICU-01",
                start_tick=50,
                duration_ticks=120,
                intensity=1.0,
                source_ip="203.0.113.10",
                label="volumetric flood",
            )
        ],
        expectations={
            "expected_policy_decision": "auto_allowed",
            "expected_action_class": "traffic_blocking",
        },
    )


def recon_then_pivot() -> ScenarioSpec:
    """Multi-stage: scan -> workstation compromise -> clinical pivot."""
    return ScenarioSpec(
        scenario_id="recon_then_pivot",
        description=(
            "Multi-stage intrusion: reconnaissance scanning, credential brute "
            "force against a workstation, then a pivot to an ICU infusion pump. "
            "Tests incident correlation across devices and the escalation of "
            "clinical risk as the attack moves from admin to clinical VLAN."
        ),
        seed=20260106,
        total_ticks=420,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.PORT_SCAN,
                target_device_id="GW-ICU-01",
                start_tick=30,
                duration_ticks=25,
                source_ip="203.0.113.99",
                label="external reconnaissance",
            ),
            AttackSpec(
                attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
                target_device_id="WS-NURSE-01",
                start_tick=70,
                duration_ticks=35,
                source_ip="203.0.113.99",
                label="initial access",
            ),
            AttackSpec(
                attack_type=AttackType.RECONNAISSANCE,
                target_device_id="ECG-ICU-01",
                start_tick=130,
                duration_ticks=30,
                source_ip="10.0.10.44",
                label="internal discovery from foothold",
            ),
            AttackSpec(
                attack_type=AttackType.MALICIOUS_COMMAND,
                target_device_id="PUMP-WARD-02",
                start_tick=180,
                duration_ticks=120,
                source_ip="10.0.10.44",
                params={"target_rate_ml_h": 95.0},
                label="pivot to clinical device",
            ),
        ],
        expectations={"multi_device_correlation": True, "escalating_clinical_risk": True},
    )


def mitm_monitor() -> ScenarioSpec:
    """MITM against the ICU monitor: blinds clinicians without harming therapy."""
    return ScenarioSpec(
        scenario_id="mitm_monitor",
        description=(
            "ARP-spoofing-enabled MITM against the ICU patient monitor with "
            "telemetry spoofing. The monitor delivers no therapy, so direct "
            "clinical risk is moderate rather than severe — but clinicians are "
            "blinded. Tests that the clinical-risk term distinguishes therapy "
            "delivery from monitoring loss."
        ),
        seed=20260107,
        total_ticks=300,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.ARP_SPOOFING,
                target_device_id="ECG-ICU-01",
                start_tick=40,
                duration_ticks=140,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
            ),
            AttackSpec(
                attack_type=AttackType.MITM,
                target_device_id="ECG-ICU-01",
                start_tick=55,
                duration_ticks=125,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
            ),
            AttackSpec(
                attack_type=AttackType.SPOOFED_TELEMETRY,
                target_device_id="ECG-ICU-01",
                start_tick=60,
                duration_ticks=120,
                source_ip="10.0.10.44",
            ),
        ],
        expectations={"expected_clinical_risk_band": ["moderate", "high"]},
    )


def dos_on_ventilator() -> ScenarioSpec:
    """DoS against a ventilator: the hardest trade-off in the platform."""
    return ScenarioSpec(
        scenario_id="dos_on_ventilator",
        description=(
            "DoS flood against VENT-ICU-02, which HAS a redundant peer and "
            "supports safe failover. Contrast with s2: because a safe clinical "
            "alternative exists, a higher-impact response becomes defensible. "
            "Tests that response-impact assessment uses redundancy."
        ),
        seed=20260108,
        total_ticks=300,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.DOS,
                target_device_id="VENT-ICU-02",
                start_tick=60,
                duration_ticks=150,
                intensity=1.0,
                source_ip="203.0.113.55",
            )
        ],
        expectations={"redundancy_enables_higher_impact_action": True},
    )


# ---------------------------------------------------------------------------
# Stealth / low-intensity scenarios
# ---------------------------------------------------------------------------
# RESEARCH VALIDITY: a corpus containing only full-intensity attacks is
# trivially separable, and a detector trained on it reports a meaningless
# F1 near 1.0 while failing on anything subtle. A 14,000 pps flood IS
# obvious - that is correct, not a defect - but a realistic evaluation corpus
# must also contain attacks that sit inside the benign distribution.
# These scenarios supply that hard tail. See docs/detection-validity.md.


def stealth_slow_recon() -> ScenarioSpec:
    """Low-and-slow scanning that stays within benign traffic levels."""
    return ScenarioSpec(
        scenario_id="stealth_slow_recon",
        description=(
            "Low-and-slow reconnaissance at 6% of normal scan intensity, "
            "spread over a long window so per-window volume stays inside the "
            "benign range. Separable only by combining port-spread with "
            "timing regularity, not by any volume threshold."
        ),
        seed=20260110,
        total_ticks=600,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.RECONNAISSANCE,
                target_device_id="GW-ICU-01",
                start_tick=120,
                duration_ticks=380,
                intensity=0.06,
                source_ip="203.0.113.201",
                label="stealth scan inside benign envelope",
            )
        ],
        expectations={"difficulty": "hard", "purpose": "low_intensity_detection"},
    )


def stealth_low_rate_dos() -> ScenarioSpec:
    """Degradation-only DoS overlapping benign burst traffic."""
    return ScenarioSpec(
        scenario_id="stealth_low_rate_dos",
        description=(
            "Low-rate DoS at 1.5% intensity against the ICU gateway, chosen "
            "to sit inside the heavy tail of benign backup and imaging "
            "bursts. Volume thresholds cannot separate it from a nightly "
            "backup; the distinguishing signal is the SYN/connection "
            "structure, not the rate."
        ),
        seed=20260111,
        total_ticks=600,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.DOS,
                target_device_id="GW-ICU-01",
                start_tick=150,
                duration_ticks=320,
                intensity=0.015,
                source_ip="203.0.113.202",
                label="low-rate degradation",
            )
        ],
        expectations={"difficulty": "hard", "purpose": "low_intensity_detection"},
    )


def stealth_passive_mitm() -> ScenarioSpec:
    """TLS-preserving MITM with minimal added latency."""
    return ScenarioSpec(
        scenario_id="stealth_passive_mitm",
        description=(
            "Passive MITM against the ICU monitor at 12% intensity, preserving "
            "TLS and adding only a few milliseconds of relay latency - inside "
            "the benign congestion-spike range. The ARP positioning is brief "
            "and low-volume. This is the hardest case in the corpus."
        ),
        seed=20260112,
        total_ticks=600,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.ARP_SPOOFING,
                target_device_id="ECG-ICU-01",
                start_tick=140,
                duration_ticks=40,
                intensity=0.10,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
            ),
            AttackSpec(
                attack_type=AttackType.MITM,
                target_device_id="ECG-ICU-01",
                start_tick=150,
                duration_ticks=330,
                intensity=0.12,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
            ),
        ],
        expectations={"difficulty": "very_hard", "purpose": "low_intensity_detection"},
    )


def stealth_credential_creep() -> ScenarioSpec:
    """Slow credential guessing below lockout thresholds."""
    return ScenarioSpec(
        scenario_id="stealth_credential_creep",
        description=(
            "Credential guessing at 5% intensity - a handful of attempts per "
            "window, below any lockout threshold and inside the range produced "
            "by staff mistyping passwords. Requires correlating the attempt "
            "pattern over time rather than counting failures in one window."
        ),
        seed=20260113,
        total_ticks=600,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            AttackSpec(
                attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
                target_device_id="WS-NURSE-01",
                start_tick=130,
                duration_ticks=350,
                intensity=0.05,
                source_ip="203.0.113.203",
            )
        ],
        expectations={"difficulty": "hard", "purpose": "low_intensity_detection"},
    )


def mixed_difficulty_corpus() -> ScenarioSpec:
    """Mixed-intensity corpus spanning obvious to stealthy.

    This is the scenario detection models are trained and evaluated on, so
    that reported metrics reflect a realistic difficulty spread rather than
    only the easy tail.
    """
    return ScenarioSpec(
        scenario_id="mixed_difficulty_corpus",
        description=(
            "Training/evaluation corpus spanning the full intensity range: "
            "obvious floods, moderate attacks, and stealth attacks that sit "
            "inside the benign distribution. Intended as the primary corpus "
            "for simulator-based detection experiments so that metrics are "
            "not dominated by trivially separable high-intensity traffic."
        ),
        seed=20260114,
        total_ticks=900,
        start_time=START,
        devices=standard_fleet(),
        attacks=[
            # --- obvious: full-intensity flood -------------------------
            AttackSpec(
                attack_type=AttackType.DDOS,
                target_device_id="GW-ICU-01",
                start_tick=60,
                duration_ticks=40,
                intensity=1.0,
                source_ip="203.0.113.10",
                label="obvious",
            ),
            # --- moderate ----------------------------------------------
            AttackSpec(
                attack_type=AttackType.PORT_SCAN,
                target_device_id="GW-ICU-01",
                start_tick=150,
                duration_ticks=30,
                intensity=0.35,
                source_ip="203.0.113.11",
                label="moderate",
            ),
            AttackSpec(
                attack_type=AttackType.DOS,
                target_device_id="VENT-ICU-02",
                start_tick=230,
                duration_ticks=45,
                intensity=0.30,
                source_ip="203.0.113.12",
                label="moderate",
            ),
            # --- stealth: inside the benign distribution ---------------
            AttackSpec(
                attack_type=AttackType.RECONNAISSANCE,
                target_device_id="ECG-ICU-01",
                start_tick=330,
                duration_ticks=90,
                intensity=0.07,
                source_ip="203.0.113.13",
                label="stealth",
            ),
            AttackSpec(
                attack_type=AttackType.CREDENTIAL_BRUTE_FORCE,
                target_device_id="WS-NURSE-01",
                start_tick=450,
                duration_ticks=110,
                intensity=0.06,
                source_ip="203.0.113.14",
                label="stealth",
            ),
            AttackSpec(
                attack_type=AttackType.ARP_SPOOFING,
                target_device_id="PUMP-ICU-01",
                start_tick=580,
                duration_ticks=35,
                intensity=0.12,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
                label="stealth",
            ),
            AttackSpec(
                attack_type=AttackType.MITM,
                target_device_id="PUMP-ICU-01",
                start_tick=590,
                duration_ticks=120,
                intensity=0.15,
                source_ip="10.0.10.44",
                source_mac="02:1a:11:00:00:44",
                label="stealth",
            ),
            # --- host-level --------------------------------------------
            AttackSpec(
                attack_type=AttackType.MALICIOUS_COMMAND,
                target_device_id="PUMP-WARD-02",
                start_tick=740,
                duration_ticks=90,
                intensity=1.0,
                source_ip="10.0.10.44",
                params={"target_rate_ml_h": 72.0},
                label="host-level",
            ),
        ],
        expectations={
            "difficulty": "mixed",
            "purpose": "primary_detection_corpus",
            "intensity_range": [0.06, 1.0],
        },
    )


SCENARIOS = {
    "baseline_normal": baseline_normal,
    "s1_noncritical_compromise": s1_noncritical_compromise,
    "s2_ventilator_compromise": s2_ventilator_compromise,
    "s3_recovery_failure": s3_recovery_failure,
    "network_flood_icu": network_flood_icu,
    "recon_then_pivot": recon_then_pivot,
    "mitm_monitor": mitm_monitor,
    "dos_on_ventilator": dos_on_ventilator,
    "stealth_slow_recon": stealth_slow_recon,
    "stealth_low_rate_dos": stealth_low_rate_dos,
    "stealth_passive_mitm": stealth_passive_mitm,
    "stealth_credential_creep": stealth_credential_creep,
    "mixed_difficulty_corpus": mixed_difficulty_corpus,
}

#: Scenarios whose attacks sit inside the benign distribution. Reported
#: separately so headline metrics are not dominated by easy traffic.
STEALTH_SCENARIOS = (
    "stealth_slow_recon",
    "stealth_low_rate_dos",
    "stealth_passive_mitm",
    "stealth_credential_creep",
)

#: The corpus detection models are trained and evaluated on.
PRIMARY_DETECTION_CORPUS = "mixed_difficulty_corpus"

MANDATED_SCENARIOS = (
    "s1_noncritical_compromise",
    "s2_ventilator_compromise",
    "s3_recovery_failure",
)


def get_scenario(name: str) -> ScenarioSpec:
    if name not in SCENARIOS:
        raise KeyError(f"Unknown scenario {name!r}. Available: {sorted(SCENARIOS)}")
    return SCENARIOS[name]()


def export_all(target_dir: str | Path = "configs/scenarios") -> list[Path]:
    """Write every built-in scenario to YAML so experiments cite files."""
    out_dir = Path(target_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, factory in sorted(SCENARIOS.items()):
        path = out_dir / f"{name}.yaml"
        factory().to_yaml(path)
        written.append(path)
    return written


__all__ = [
    "MANDATED_SCENARIOS",
    "PRIMARY_DETECTION_CORPUS",
    "SCENARIOS",
    "STEALTH_SCENARIOS",
    "export_all",
    "get_scenario",
    "standard_fleet",
]
