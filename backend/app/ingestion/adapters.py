"""Normalise alerts from external detectors into one internal shape.

Why alerts and not flows: the real-data detector scores 45 CICFlowMeter-style
features per flow. Suricata, Zeek and Wazuh do not emit those features, and
approximating them from other logs would feed the model inputs from a
different distribution than it was trained on. These tools have, however,
already made a detection of their own. This module turns that alert into a
`NormalizedAlert`; the API layer then opens an incident from it, so an
external detector's output enters the same investigation, policy and ledger
pipeline. No ML model is involved and no confidence is invented by us: the
confidence recorded is a documented mapping of the source's own severity.

Each adapter raises `AlertParseError` for input it cannot interpret. A
malformed alert is rejected, never guessed at. `NotAnAlertError` marks input
that is valid but not an alert (for example a Suricata `flow` or `stats`
record), which callers skip.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.schemas.enums import AttackCategory, ImpactLevel


class AlertParseError(ValueError):
    """The record is not a well-formed alert for this source."""


class NotAnAlertError(AlertParseError):
    """The record is valid for this source but is not an alert (skip it)."""


@dataclass(frozen=True)
class NormalizedAlert:
    source: str
    candidates: tuple[str, ...]  # names/IPs that may identify the affected device
    attack_type: AttackCategory
    confidence: float
    severity_hint: ImpactLevel
    timestamp: datetime
    summary: str
    reference: str
    details: dict[str, str] = field(default_factory=dict)


# Ordered: the first matching pattern wins.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (value, re.compile(pattern, re.IGNORECASE))
    for value, pattern in (
        ("mqtt_based", r"\bmqtt\b"),
        ("ddos", r"\bddos\b|distributed denial"),
        ("dos", r"\bdos\b|denial[- ]of[- ]service|\bflood"),
        ("spoofing", r"spoof|arp poison|arp cache"),
        ("mitm_injection", r"\bmitm\b|man[- ]in[- ]the[- ]middle|packet injection|command injection"),
        ("reconnaissance", r"\bscan|recon|port ?sweep|information leak"),
    )
)


def classify_attack(text: str) -> AttackCategory:
    """Keyword mapping from an alert's own wording to our attack categories.
    Anything unrecognised is `unknown`, not forced into the nearest class."""
    for value, pattern in _PATTERNS:
        if pattern.search(text):
            return AttackCategory(value)
    return AttackCategory("unknown")


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601, including Suricata/Wazuh's `+0000` offset form. A missing
    value means "now"; a present but unparseable one is rejected."""
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, str):
        raise AlertParseError(f"timestamp must be a string, got {type(value).__name__}")
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip())
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AlertParseError(f"unparseable timestamp {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _s(value: Any, limit: int = 200) -> str:
    return str(value)[:limit]


def _clean(details: dict[str, Any]) -> dict[str, str]:
    return {k: _s(v) for k, v in details.items() if v not in (None, "", [])}


# Suricata severity: 1 = high, 2 = medium, 3 = low.
_SURICATA_CONFIDENCE = {1: 0.90, 2: 0.75, 3: 0.60}
_SURICATA_IMPACT = {1: ImpactLevel("high"), 2: ImpactLevel("medium"), 3: ImpactLevel("low")}


def parse_suricata_eve(record: Any) -> NormalizedAlert:
    if not isinstance(record, dict):
        raise AlertParseError("Suricata record must be a JSON object")
    if record.get("event_type") != "alert":
        raise NotAnAlertError(f"event_type {record.get('event_type')!r} is not an alert")
    alert = record.get("alert")
    if not isinstance(alert, dict):
        raise AlertParseError("Suricata alert record has no 'alert' object")
    signature = _s(alert.get("signature", ""))
    category = _s(alert.get("category", ""))
    try:
        severity = int(alert.get("severity", 3))
    except (TypeError, ValueError) as exc:
        raise AlertParseError(f"bad alert.severity {alert.get('severity')!r}") from exc
    timestamp = parse_timestamp(record.get("timestamp"))
    candidates = tuple(_s(record[k]) for k in ("dest_ip", "src_ip") if record.get(k))
    reference = f"suricata:flow={record.get('flow_id', 'none')}:sid={alert.get('signature_id', 'none')}:{timestamp.isoformat()}"
    return NormalizedAlert(
        source="suricata_eve",
        candidates=candidates,
        attack_type=classify_attack(f"{signature} {category}"),
        confidence=_SURICATA_CONFIDENCE.get(severity, 0.50),
        severity_hint=_SURICATA_IMPACT.get(severity, ImpactLevel("low")),
        timestamp=timestamp,
        summary=signature or category or "suricata alert",
        reference=reference,
        details=_clean({
            "signature": signature, "category": category, "severity": severity,
            "proto": record.get("proto"), "src_ip": record.get("src_ip"), "dest_ip": record.get("dest_ip"),
        }),
    )


def _wazuh_confidence(level: int) -> float:
    return 0.90 if level >= 12 else 0.75 if level >= 8 else 0.60 if level >= 5 else 0.50


def _wazuh_impact(level: int) -> ImpactLevel:
    return ImpactLevel("high") if level >= 12 else ImpactLevel("medium") if level >= 8 else ImpactLevel("low")


def parse_wazuh(record: Any) -> NormalizedAlert:
    if not isinstance(record, dict):
        raise AlertParseError("Wazuh record must be a JSON object")
    rule = record.get("rule")
    if not isinstance(rule, dict):
        raise AlertParseError("Wazuh alert has no 'rule' object")
    try:
        level = int(rule["level"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AlertParseError("Wazuh rule.level is missing or not an integer") from exc
    description = _s(rule.get("description", ""))
    groups = rule.get("groups") or []
    text = f"{description} {' '.join(map(str, groups)) if isinstance(groups, list) else groups}"
    agent = record.get("agent") if isinstance(record.get("agent"), dict) else {}
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    timestamp = parse_timestamp(record.get("timestamp"))
    candidates = tuple(
        _s(v) for v in (agent.get("name"), agent.get("ip"), data.get("srcip"), data.get("dstip")) if v
    )
    return NormalizedAlert(
        source="wazuh",
        candidates=candidates,
        attack_type=classify_attack(text),
        confidence=_wazuh_confidence(level),
        severity_hint=_wazuh_impact(level),
        timestamp=timestamp,
        summary=description or "wazuh alert",
        reference=f"wazuh:{record.get('id', rule.get('id', 'none'))}:{timestamp.isoformat()}",
        details=_clean({
            "rule_id": rule.get("id"), "rule_level": level, "description": description,
            "agent": agent.get("name"), "srcip": data.get("srcip"),
        }),
    )


def parse_generic(record: Any) -> NormalizedAlert:
    """The documented webhook shape for any other detector:
    {device_id, attack_type, confidence?, severity?, timestamp?, description?, reference?}."""
    if not isinstance(record, dict):
        raise AlertParseError("alert must be a JSON object")
    try:
        attack_type = AttackCategory(record.get("attack_type", "unknown"))
    except ValueError as exc:
        raise AlertParseError(f"unknown attack_type {record.get('attack_type')!r}") from exc
    try:
        confidence = float(record.get("confidence", 0.8))
    except (TypeError, ValueError) as exc:
        raise AlertParseError("confidence must be a number") from exc
    if not 0.0 <= confidence <= 1.0:
        raise AlertParseError(f"confidence {confidence} is outside [0, 1]")
    try:
        severity = ImpactLevel(record.get("severity", "medium"))
    except ValueError as exc:
        raise AlertParseError(f"bad severity {record.get('severity')!r}") from exc
    timestamp = parse_timestamp(record.get("timestamp"))
    device = record.get("device_id")
    return NormalizedAlert(
        source="generic",
        candidates=(_s(device),) if device else (),
        attack_type=attack_type,
        confidence=confidence,
        severity_hint=severity,
        timestamp=timestamp,
        summary=_s(record.get("description", "external alert")),
        reference=_s(record.get("reference") or f"generic:{timestamp.isoformat()}"),
        details=_clean({"description": record.get("description")}),
    )


ADAPTERS = {
    "generic": parse_generic,
    "suricata_eve": parse_suricata_eve,
    "wazuh": parse_wazuh,
}
