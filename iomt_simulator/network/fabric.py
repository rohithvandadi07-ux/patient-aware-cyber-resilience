"""Simulated hospital network fabric.

Generates per-tick network flow records between assets. Flows are the
primary detection surface for the network-borne threat classes (DoS/DDoS,
scanning, ARP spoofing, MITM), mirroring the feature families found in the
public IoMT security datasets (packet rates, byte counts, flow duration,
inter-arrival statistics, flag distributions).
"""

from __future__ import annotations

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

        events: list[NormalisedEvent] = []

        # --- benign egress flow to the clinical server --------------------
        pps = max(0.5, base_pps * restriction + self._jitter(base_pps * 0.09))
        pkt_bytes = max(64.0, base_bytes + self._jitter(base_bytes * 0.06))
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
                syn_ratio=0.02 + abs(self._jitter(0.004)),
                distinct_dst_ports=1.0,
                arp_changes=0.0,
                ttl_variance=0.4 + abs(self._jitter(0.1)),
                duplicate_mac=0.0,
                label=None,
            )
        )

        # --- attack-driven flows -----------------------------------------
        for a in attacks:
            if not a.active_at(now):
                continue
            t = a.attack_type
            if t in {AttackType.DOS, AttackType.DDOS}:
                sources = 1 if t == AttackType.DOS else 24
                flood_pps = (5200.0 if t == AttackType.DOS else 14000.0) * a.intensity
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
                            syn_ratio=0.88 + abs(self._jitter(0.02)),
                            distinct_dst_ports=1.0,
                            arp_changes=0.0,
                            ttl_variance=0.5,
                            duplicate_mac=0.0,
                            label=t,
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
                        pps=max(1.0, 70.0 * a.intensity + self._jitter(6.0)),
                        pkt_bytes=max(54.0, 60.0 + self._jitter(3.0)),
                        syn_ratio=0.97,
                        distinct_dst_ports=max(2.0, 48.0 * a.intensity + self._jitter(3.0)),
                        arp_changes=0.0,
                        ttl_variance=0.6,
                        duplicate_mac=0.0,
                        label=t,
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
                        pps=max(1.0, 14.0 * a.intensity + self._jitter(1.6)),
                        pkt_bytes=42.0,
                        syn_ratio=0.0,
                        distinct_dst_ports=0.0,
                        arp_changes=max(1.0, 9.0 * a.intensity + self._jitter(0.8)),
                        ttl_variance=0.2,
                        duplicate_mac=1.0,
                        label=t,
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
                        arp_changes=2.0 * a.intensity,
                        ttl_variance=4.6 * a.intensity + abs(self._jitter(0.3)),
                        duplicate_mac=1.0,
                        label=t,
                        extra_measurements={
                            "rtt_ms": 42.0 * a.intensity + abs(self._jitter(2.0)),
                            "tls_downgrade": 1.0,
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
