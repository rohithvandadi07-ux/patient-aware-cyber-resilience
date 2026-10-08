"""Event-to-incident correlation.

Decides whether a new detection belongs to an existing incident or opens a
new one. This matters for the resilience metrics: if every detection window
opened its own incident, a single 90-second attack would produce eighteen
"incidents" and MTTD/MTTR would be meaningless.

Correlation keys, in order of strength:

1. **Same device + same attack type + within the correlation window** —
   almost certainly the same ongoing attack.
2. **Same device + different attack type + within the window** — a
   multi-stage attack on one asset (ARP spoofing then MITM); correlated so
   the incident timeline shows the progression.
3. **Same source identity across devices + within the window** — lateral
   movement; correlated so the operator sees one campaign rather than
   several unrelated alerts.

Rule 3 is the one that makes `recon_then_pivot` legible as a single
intrusion rather than four disconnected events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.app.domain.models import DetectionResult, Incident, NormalisedEvent


@dataclass(frozen=True)
class CorrelationConfig:
    """Correlation parameters. Swept in the sensitivity analysis."""

    #: Same device, same attack type.
    same_attack_window_seconds: float = 300.0
    #: Same device, different attack type (multi-stage on one asset).
    multistage_window_seconds: float = 600.0
    #: Same attacker identity across devices (lateral movement).
    campaign_window_seconds: float = 900.0
    #: Correlate across devices at all?
    correlate_across_devices: bool = True


@dataclass
class CorrelationDecision:
    """Why a detection was or was not attached to an existing incident."""

    incident_id: str | None
    rule: str
    reason: str
    confidence: float = 1.0

    @property
    def is_new_incident(self) -> bool:
        return self.incident_id is None


class IncidentCorrelator:
    """Matches detections to open incidents."""

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()

    def correlate(
        self,
        detection: DetectionResult,
        open_incidents: list[Incident],
        source_identities: set[str] | None = None,
    ) -> CorrelationDecision:
        """Find the incident this detection belongs to, if any.

        ``source_identities`` is the set of attacker-side identifiers
        (source IPs/MACs) observed in this detection's evidence. Passed
        explicitly rather than read from the detection, because the
        detection itself must not carry identity features (they leak; see
        ``cybersecurity/schema.py``).
        """
        now = detection.timestamp
        candidates = [i for i in open_incidents if i.state.value not in {"resolved", "failed"}]
        if not candidates:
            return CorrelationDecision(
                None, "no_open_incidents", "no open incident to correlate against"
            )

        # Rule 1: same device, same attack type.
        for inc in sorted(candidates, key=lambda i: i.updated_at, reverse=True):
            if (
                inc.device_id == detection.device_id
                and inc.attack_type is detection.attack_type
                and self._within(now, inc.updated_at, self.config.same_attack_window_seconds)
            ):
                return CorrelationDecision(
                    inc.incident_id,
                    "same_device_same_attack",
                    (
                        f"{detection.attack_type.value} on {detection.device_id} "
                        f"already tracked by {inc.incident_id}, last updated "
                        f"{(now - inc.updated_at).total_seconds():.0f}s ago"
                    ),
                )

        # Rule 2: same device, different attack type (multi-stage).
        for inc in sorted(candidates, key=lambda i: i.updated_at, reverse=True):
            if inc.device_id == detection.device_id and self._within(
                now, inc.updated_at, self.config.multistage_window_seconds
            ):
                return CorrelationDecision(
                    inc.incident_id,
                    "same_device_multistage",
                    (
                        f"new stage {detection.attack_type.value} on "
                        f"{detection.device_id}, already under investigation as "
                        f"{inc.incident_id} ({inc.attack_type.value})"
                    ),
                    confidence=0.8,
                )

        # Rule 3: same attacker identity across devices (lateral movement).
        if self.config.correlate_across_devices and source_identities:
            for inc in sorted(candidates, key=lambda i: i.updated_at, reverse=True):
                if not self._within(now, inc.updated_at, self.config.campaign_window_seconds):
                    continue
                known = self._incident_source_identities(inc)
                shared = known & source_identities
                if shared:
                    return CorrelationDecision(
                        inc.incident_id,
                        "shared_source_identity",
                        (
                            f"source {sorted(shared)} already observed in "
                            f"{inc.incident_id} on {inc.device_id}; correlating as "
                            "lateral movement within one campaign"
                        ),
                        confidence=0.7,
                    )

        return CorrelationDecision(
            None,
            "no_match",
            (
                f"{detection.attack_type.value} on {detection.device_id} does not "
                "match any open incident within the correlation windows"
            ),
        )

    @staticmethod
    def _within(now: datetime, then: datetime, seconds: float) -> bool:
        return abs((now - then).total_seconds()) <= seconds

    @staticmethod
    def _incident_source_identities(incident: Incident) -> set[str]:
        """Attacker identities recorded in an incident's evidence payloads."""
        out: set[str] = set()
        for ev in incident.evidence:
            for key in ("source_ips", "source_macs", "source_identities"):
                val = ev.payload.get(key)
                if isinstance(val, list):
                    out.update(str(v) for v in val)
                elif isinstance(val, str):
                    out.add(val)
        return out


def extract_source_identities(events: list[NormalisedEvent]) -> set[str]:
    """Collect attacker-side identifiers from the events behind a detection.

    Only non-local identities are returned: the defended device's own
    address is not an attacker identity, and including it would correlate
    every incident on that device into one.
    """
    out: set[str] = set()
    device_ips = {e.destination_ip for e in events if e.destination_ip}
    for e in events:
        if e.source_ip and e.source_ip not in device_ips:
            out.add(e.source_ip)
        if e.source_mac:
            out.add(e.source_mac)
    return out


__all__ = [
    "CorrelationConfig",
    "CorrelationDecision",
    "IncidentCorrelator",
    "extract_source_identities",
]
