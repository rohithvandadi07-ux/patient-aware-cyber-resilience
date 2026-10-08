"""Simulated hospital network fabric.

Generates per-tick network flow records between assets. Flows are the
primary detection surface for the network-borne threat classes (DoS/DDoS,
scanning, ARP spoofing, MITM), mirroring the feature families found in the
public IoMT security datasets (packet rates, byte counts, flow duration,
inter-arrival statistics, flag distributions).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime

from backend.app.domain.enums import AttackType, EventKind, NetworkState
from backend.app.domain.ids import IdFactory
from backend.app.domain.models import NormalisedEvent
from iomt_simulator.base import AttackEffect, derive_seed

# Baseline traffic profile per device type: (pps, mean packet bytes).
BASELINE_PROFILE: dict[str, tuple[float, float]] = {
    "infusion_pump": (9.0, 180.0),
    "ventilator": (16.0, 240.0),
    "ecg_monitor": (55.0, 320.0),
    "workstation": (120.0, 640.0),
    "network_gateway": (820.0, 740.0),
}

CLINICAL_SERVER_IP = "10.0.20.10"


@dataclass
class NetworkFabric:
    """Emits normalised flow events for every reachable asset each tick."""

    scenario_seed: int
    ids: IdFactory
    tick_seconds: float = 1.0
    rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self.rng = random.Random(derive_seed(self.scenario_seed, "__network__"))
        self._phase = 0.0

    def _jitter(self, scale: float) -> float:
        return max(-3.0 * scale, min(3.0 * scale, self.rng.gauss(0.0, scale)))

    def flows_for_device(
        self,
        now: datetime,
        device_id: str,
        device_type: str,
        ip: str,
        mac: str,
        network_state: NetworkState,
        attacks: list[AttackEffect],
    ) -> list[NormalisedEvent]:
        """Generate this tick's flow events for one device."""
        if network_state in {NetworkState.ISOLATED, NetworkState.UNREACHABLE}:
            return []

        base_pps, base_bytes = BASELINE_PROFILE.get(device_type, (20.0, 260.0))
        restriction = {
            NetworkState.NORMAL: 1.0,
            NetworkState.RESTRICTED: 0.35,
            NetworkState.SEGMENTED: 0.15,
        }.get(network_state, 1.0)

        # RESEARCH VALIDITY: benign load must be heavy-tailed, not constant.
        # With a near-constant baseline, ANY additive attack traffic is
        # separable by volume alone and single-feature AUC reaches 1.0.
        # Real wards show diurnal variation plus bursts from backups, imaging
        # transfers and EHR synchronisation that overlap attack volumes.
        # See docs/detection-validity.md.
        diurnal = 1.0 + 0.45 * math.sin(self._phase)
        self._phase += 0.0045 * self.tick_seconds
        burst = 1.0
        if self.rng.random() < 0.07:
            # Backup / imaging transfer / EHR sync: heavy-tailed burst that
            # can reach flood-comparable rates.
            burst = self.rng.lognormvariate(1.5, 1.25)
        load = max(0.25, diurnal * burst)
        base_pps *= load
        base_bytes *= max(0.5, 1.0 + self._jitter(0.25))

        events: list[NormalisedEvent] = []

        # --- benign egress flow to the clinical server --------------------
        #
        # RESEARCH VALIDITY: benign traffic must legitimately occupy the same
        # feature dimensions that attacks elevate. If an indicator is zero on
        # every benign flow and non-zero only under attack, its *presence*
        # becomes the label and any classifier reports a meaningless F1 near
        # 1.0. Every benign value below corresponds to a real phenomenon in
        # hospital networks; their absence was a defect, not realism.
        # See docs/detection-validity.md.
        pps = max(0.5, base_pps * restriction + self._jitter(base_pps * 0.09))
        pkt_bytes = max(64.0, base_bytes + self._jitter(base_bytes * 0.06))

        # Normal round-trip latency, occasionally spiking under congestion.
        benign_rtt = max(0.4, 3.2 + self._jitter(1.1))
        if self.rng.random() < 0.04:
            benign_rtt += abs(self.rng.gauss(18.0, 9.0))  # transient congestion

        # Legacy devices that genuinely negotiate plaintext. Common in
        # hospitals and a frequent source of false MITM alerts.
        benign_tls_downgrade = 1.0 if self.rng.random() < 0.035 else 0.0

        # Transient MAC conflicts from DHCP lease churn, VM migration or NIC
        # failover - real causes unrelated to ARP spoofing.
        benign_dup_mac = 1.0 if self.rng.random() < 0.025 else 0.0
        benign_arp_churn = abs(self._jitter(0.5)) + (
            self.rng.uniform(1.0, 4.0) if benign_dup_mac else 0.0
        )

        events.append(
            self._flow(
                now=now,
                device_id=device_id,
                src_ip=ip,
                dst_ip=CLINICAL_SERVER_IP,
                src_mac=mac,
                protocol="tcp",
                src_port=self.rng.randint(32768, 60999),
                dst_port=8883,
                pps=pps,
                pkt_bytes=pkt_bytes,
                # Connection-establishment bursts (backup jobs, imaging
                # transfers, mass reconnects after a link flap) legitimately
                # drive the benign SYN ratio high, so a SYN threshold alone
                # cannot separate floods from normal operations.
                syn_ratio=(
                    min(0.96, self.rng.uniform(0.45, 0.92))
                    if self.rng.random() < 0.06
                    else 0.02 + abs(self._jitter(0.004))
                ),
                # A device legitimately contacts several services (telemetry
                # broker, time, name resolution, update endpoint), and a
                # management sweep contacts many. If benign port spread were
                # always 1.0, any spread would be an attack-only signal and
                # `distinct_dst_ports` alone would reach AUC 1.0.
                distinct_dst_ports=(
                    self.rng.uniform(8.0, 34.0)
                    if self.rng.random() < 0.05
                    else max(1.0, self.rng.gauss(2.4, 1.1))
                ),
                arp_changes=benign_arp_churn,
                ttl_variance=max(0.1, 1.3 + self._jitter(0.6)),
                duplicate_mac=benign_dup_mac,
                label=None,
                extra_measurements={
                    "rtt_ms": benign_rtt,
                    "tls_downgrade": benign_tls_downgrade,
                },
            )
        )

        # --- benign peer churn -------------------------------------------
        # ROOT-CAUSE FIX. Previously every benign flow used the same two or
        # three peer addresses, so an attack from a new source made "an
        # unseen peer appeared" a perfect label. Any feature touching flow
        # identity or record structure then separated the classes, which is
        # why distinct_dst_hosts, packets, syn_ratio and is_arp each reached
        # AUC ~1.0 in turn: they were all proxies for the same artifact.
        #
        # Real wards see a churning peer population: roaming clinician
        # devices, imaging modalities, vendor update endpoints, other wards'
        # gateways, EHR replicas. With that churn present, a new peer is
        # unremarkable and detection must rely on BEHAVIOUR.
        # See docs/detection-validity.md.
        n_peers = self.rng.choice([0, 0, 1, 1, 2, 3])
        for _ in range(n_peers):
            peer_ip = self.rng.choice(
                [
                    f"10.0.{self.rng.randint(20, 29)}.{self.rng.randint(2, 254)}",
                    f"10.0.{self.rng.randint(30, 39)}.{self.rng.randint(2, 254)}",
                    f"172.16.{self.rng.randint(0, 31)}.{self.rng.randint(2, 254)}",
                ]
            )
            events.append(
                self._flow(
                    now=now,
                    device_id=device_id,
                    src_ip=ip,
                    dst_ip=peer_ip,
                    src_mac=mac,
                    protocol=self.rng.choice(["tcp", "tcp", "udp"]),
                    src_port=self.rng.randint(32768, 60999),
                    dst_port=self.rng.choice([443, 8883, 445, 139, 5000, 8080, 2575]),
                    pps=max(0.3, abs(self.rng.lognormvariate(1.2, 1.1))),
                    pkt_bytes=max(64.0, 210.0 + self._jitter(90.0)),
                    syn_ratio=(
                        self.rng.uniform(0.3, 0.9)
                        if self.rng.random() < 0.12
                        else 0.03 + abs(self._jitter(0.01))
                    ),
                    distinct_dst_ports=max(1.0, self.rng.gauss(2.0, 1.2)),
                    arp_changes=abs(self._jitter(0.5)),
                    ttl_variance=max(0.1, 1.4 + self._jitter(0.8)),
                    duplicate_mac=1.0 if self.rng.random() < 0.02 else 0.0,
                    label=None,
                    extra_measurements={
                        "rtt_ms": max(0.3, abs(self.rng.lognormvariate(1.3, 0.9))),
                        "tls_downgrade": 1.0 if self.rng.random() < 0.04 else 0.0,
                    },
                )
            )

        # --- benign infrastructure chatter -------------------------------
        # DNS/NTP/SNMP keep the benign protocol mix from being pure TCP, so
        # protocol identity alone cannot separate classes.
        if self.rng.random() < 0.45:
            svc_port, _svc_name = self.rng.choice(
                [(53, "dns"), (123, "ntp"), (161, "snmp"), (5353, "mdns")]
            )
            events.append(
                self._flow(
                    now=now,
                    device_id=device_id,
                    src_ip=ip,
                    dst_ip="10.0.20.5",
                    src_mac=mac,
                    protocol="udp",
                    src_port=self.rng.randint(32768, 60999),
                    dst_port=svc_port,
                    pps=max(0.2, 2.4 + self._jitter(0.9)),
                    pkt_bytes=max(64.0, 118.0 + self._jitter(22.0)),
                    syn_ratio=0.0,
                    distinct_dst_ports=1.0,
                    arp_changes=abs(self._jitter(0.4)),
                    ttl_variance=max(0.1, 1.2 + self._jitter(0.5)),
                    duplicate_mac=0.0,
                    label=None,
                    extra_measurements={
                        "rtt_ms": max(0.3, 2.1 + self._jitter(0.8)),
                        "tls_downgrade": 0.0,
                    },
                )
            )

        # --- benign management polling -----------------------------------
        # A monitoring system that legitimately touches several ports, so
        # distinct_dst_ports is not an attack-only signal.
        if self.rng.random() < 0.18:
            events.append(
                self._flow(
                    now=now,
                    device_id=device_id,
                    src_ip="10.0.20.9",
                    dst_ip=ip,
                    src_mac="02:1a:11:00:00:09",
                    protocol="tcp",
                    src_port=self.rng.randint(32768, 60999),
                    dst_port=self.rng.choice([22, 80, 443, 8883]),
                    pps=max(0.5, 5.5 + self._jitter(1.8)),
                    pkt_bytes=max(64.0, 160.0 + self._jitter(28.0)),
                    syn_ratio=0.14 + abs(self._jitter(0.05)),
                    distinct_dst_ports=self.rng.uniform(3.0, 9.0),
                    arp_changes=abs(self._jitter(0.3)),
                    ttl_variance=max(0.1, 1.5 + self._jitter(0.6)),
                    duplicate_mac=0.0,
                    label=None,
                    extra_measurements={
                        "rtt_ms": max(0.3, 4.0 + self._jitter(1.4)),
                        "tls_downgrade": 0.0,
                    },
                )
            )

        # --- benign ARP resolution ---------------------------------------
        # Every host performs ARP. A simulator where only the attacker emits
        # ARP makes protocol identity a perfect label; `is_arp` alone then
        # reaches AUC 1.0. See docs/detection-validity.md.
        if self.rng.random() < 0.30:
            events.append(
                self._flow(
                    now=now,
                    device_id=device_id,
                    src_ip=ip,
                    dst_ip="10.0.0.1",
                    src_mac=mac,
                    protocol="arp",
                    src_port=None,
                    dst_port=None,
                    pps=max(0.2, 1.6 + self._jitter(0.7)),
                    pkt_bytes=42.0,
                    syn_ratio=0.0,
                    distinct_dst_ports=0.0,
                    # Routine cache refresh churn, occasionally elevated by
                    # DHCP lease renewal sweeps.
                    arp_changes=(
                        self.rng.uniform(2.0, 6.0)
                        if self.rng.random() < 0.08
                        else abs(self._jitter(0.6))
                    ),
                    ttl_variance=max(0.1, 1.1 + self._jitter(0.4)),
                    duplicate_mac=1.0 if self.rng.random() < 0.03 else 0.0,
                    label=None,
                    extra_measurements={
                        "rtt_ms": max(0.2, 1.4 + self._jitter(0.5)),
                        "tls_downgrade": 0.0,
                    },
                )
            )

        # --- attack-driven flows -----------------------------------------
        #
        # Attack intensity is perturbed per tick so that low-intensity
        # attacks fall inside the benign distribution and must be separated
        # by feature COMBINATIONS rather than any single threshold.
        for a in attacks:
            if not a.active_at(now):
                continue
            t = a.attack_type
            eff = max(0.08, a.intensity * self.rng.lognormvariate(-0.18, 0.55))
            if t in {AttackType.DOS, AttackType.DDOS}:
                sources = 1 if t == AttackType.DOS else 24
                flood_pps = (5200.0 if t == AttackType.DOS else 14000.0) * eff
                for i in range(min(sources, 4)):  # aggregate representative flows
                    share = flood_pps / min(sources, 4)
                    src = a.source_ip if sources == 1 else f"203.0.113.{10 + i}"
                    events.append(
                        self._flow(
                            now=now,
                            device_id=device_id,
                            src_ip=src,
                            dst_ip=ip,
                            src_mac=a.source_mac,
                            protocol="udp" if t == AttackType.DDOS else "tcp",
                            src_port=self.rng.randint(1024, 65535),
                            dst_port=8883,
                            pps=share + self._jitter(share * 0.05),
                            pkt_bytes=max(64.0, 92.0 + self._jitter(6.0)),
                            syn_ratio=min(0.99, 0.55 + 0.33 * eff + self._jitter(0.06)),
                            distinct_dst_ports=1.0,
                            arp_changes=abs(self._jitter(0.4)),
                            ttl_variance=max(0.1, 1.4 + self._jitter(0.7)),
                            duplicate_mac=0.0,
                            label=t,
                            extra_measurements={
                                "rtt_ms": max(0.4, 3.0 + 14.0 * eff + self._jitter(2.0)),
                                "tls_downgrade": 0.0,
                            },
                        )
                    )
            elif t in {AttackType.PORT_SCAN, AttackType.RECONNAISSANCE}:
                events.append(
                    self._flow(
                        now=now,
                        device_id=device_id,
                        src_ip=a.source_ip,
                        dst_ip=ip,
                        src_mac=a.source_mac,
                        protocol="tcp",
                        src_port=self.rng.randint(40000, 60000),
                        dst_port=self.rng.randint(1, 1024),
                        pps=max(1.0, 70.0 * eff + self._jitter(6.0)),
                        pkt_bytes=max(54.0, 60.0 + self._jitter(3.0)),
                        syn_ratio=min(0.99, 0.60 + 0.35 * eff + self._jitter(0.07)),
                        distinct_dst_ports=max(2.0, 10.0 + 40.0 * eff + self._jitter(3.0)),
                        arp_changes=abs(self._jitter(0.4)),
                        ttl_variance=max(0.1, 1.5 + self._jitter(0.7)),
                        duplicate_mac=0.0,
                        label=t,
                        extra_measurements={
                            "rtt_ms": max(0.3, 3.4 + self._jitter(1.3)),
                            "tls_downgrade": 0.0,
                        },
                    )
                )
            elif t == AttackType.ARP_SPOOFING:
                events.append(
                    self._flow(
                        now=now,
                        device_id=device_id,
                        src_ip=a.source_ip,
                        dst_ip=ip,
                        src_mac=a.source_mac,
                        protocol="arp",
                        src_port=None,
                        dst_port=None,
                        pps=max(1.0, 14.0 * eff + self._jitter(1.6)),
                        pkt_bytes=42.0,
                        syn_ratio=0.0,
                        distinct_dst_ports=0.0,
                        arp_changes=max(0.5, 2.0 + 7.0 * eff + self._jitter(0.9)),
                        ttl_variance=max(0.1, 1.2 + self._jitter(0.5)),
                        duplicate_mac=1.0,
                        label=t,
                        extra_measurements={
                            "rtt_ms": max(0.3, 3.1 + self._jitter(1.2)),
                            "tls_downgrade": 0.0,
                        },
                    )
                )
            elif t == AttackType.MITM:
                # MITM shows as relayed traffic: extra hop inflates TTL
                # variance and round-trip latency without flooding.
                events.append(
                    self._flow(
                        now=now,
                        device_id=device_id,
                        src_ip=ip,
                        dst_ip=CLINICAL_SERVER_IP,
                        src_mac=a.source_mac,
                        protocol="tcp",
                        src_port=self.rng.randint(32768, 60999),
                        dst_port=8883,
                        pps=max(0.5, pps * 0.9),
                        pkt_bytes=pkt_bytes * 1.04,
                        syn_ratio=0.03,
                        distinct_dst_ports=1.0,
                        arp_changes=max(0.3, 1.0 + 1.6 * eff + self._jitter(0.4)),
                        ttl_variance=max(0.1, 1.4 + 3.4 * eff + abs(self._jitter(0.4))),
                        duplicate_mac=1.0 if self.rng.random() < 0.75 else 0.0,
                        label=t,
                        extra_measurements={
                            # Relaying adds latency, but only sometimes enough
                            # to clear benign congestion spikes.
                            "rtt_ms": max(0.5, 6.0 + 34.0 * eff + self._jitter(3.0)),
                            # A competent MITM may preserve TLS.
                            "tls_downgrade": 1.0 if self.rng.random() < 0.6 else 0.0,
                        },
                    )
                )
        return events

    def _flow(
        self,
        *,
        now: datetime,
        device_id: str,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        protocol: str,
        src_port: int | None,
        dst_port: int | None,
        pps: float,
        pkt_bytes: float,
        syn_ratio: float,
        distinct_dst_ports: float,
        arp_changes: float,
        ttl_variance: float,
        duplicate_mac: float,
        label: AttackType | None,
        extra_measurements: dict[str, float] | None = None,
    ) -> NormalisedEvent:
        packets = max(1.0, pps * self.tick_seconds)
        total_bytes = packets * pkt_bytes
        measurements = {
            "packets": round(packets, 3),
            "packets_per_second": round(pps, 3),
            "bytes": round(total_bytes, 2),
            "bytes_per_second": round(total_bytes / self.tick_seconds, 2),
            "mean_packet_bytes": round(pkt_bytes, 3),
            "flow_duration_s": round(self.tick_seconds, 3),
            "mean_iat_ms": round(1000.0 / max(pps, 0.001), 4),
            "syn_ratio": round(min(1.0, max(0.0, syn_ratio)), 4),
            "distinct_dst_ports": round(distinct_dst_ports, 3),
            "arp_table_changes": round(arp_changes, 3),
            "ttl_variance": round(ttl_variance, 4),
            "duplicate_mac_observed": duplicate_mac,
        }
        if extra_measurements:
            measurements.update({k: round(v, 4) for k, v in extra_measurements.items()})
        return NormalisedEvent(
            event_id=self.ids.event(),
            timestamp=now,
            kind=EventKind.NETWORK_FLOW,
            device_id=device_id,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_mac=src_mac,
            protocol=protocol,
            source_port=src_port,
            destination_port=dst_port,
            measurements=measurements,
            attributes={
                "direction": "inbound" if dst_ip != CLINICAL_SERVER_IP else "outbound",
                "flow_label": "attack" if label else "benign",
            },
            ground_truth_attack=label,
            ground_truth_is_attack=label is not None,
        )


__all__ = ["BASELINE_PROFILE", "CLINICAL_SERVER_IP", "NetworkFabric"]
