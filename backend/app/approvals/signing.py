"""Ed25519-signed approvals.

An `ApprovalRecord` used to carry any `approver_identity` string, with no proof
it came from that person. With a registered public key per approver, an
approval can be verified: the signature covers the incident, the exact action
and policy rule being approved, the decision and the timestamp, so changing any
of them (or replaying an approval for another incident or action) fails
verification. Timestamps outside `max_age_s` are refused to limit replay.

Kept free of app imports so the CLI (`scripts/sign_approval.py`) can use the
exact same message builder as the server -- one definition, no drift.

Limits, stated plainly: the server holds only public keys; private-key custody
is the approver's job. The signature is verified at the API boundary and
carried in the outbox payload, but the on-chain `recordApproval` call still
stores only (incident, identity, decision, timestamp) -- putting the signature
on-chain needs a chaincode change.
"""

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MESSAGE_VERSION = 1


class ApprovalSignatureError(Exception):
    """The approval's signature is missing, invalid or stale."""


def _value(item: Any) -> Any:
    return getattr(item, "value", item)


def format_timestamp(timestamp: datetime) -> str:
    """Canonical UTC form with microseconds, e.g. 2026-10-19T10:00:00.123456Z."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def approval_message(
    incident_id: str, chosen_action: Any, policy_rule_id: str, decision: Any, timestamp: datetime
) -> bytes:
    payload = {
        "v": MESSAGE_VERSION,
        "incident_id": incident_id,
        "chosen_action": _value(chosen_action),
        "policy_rule_id": policy_rule_id,
        "decision": _value(decision),
        "ts": format_timestamp(timestamp),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_b64, validate=True), message)
    except (InvalidSignature, ValueError, binascii.Error):
        return False
    return True


def check_approval_signature(
    *,
    approval: Any,
    chosen_action: Any,
    policy_rule_id: str,
    decision_incident_id: str,
    public_keys: dict[str, str],
    require_signed: bool,
    max_age_s: float,
    now: datetime | None = None,
) -> bool:
    """True when a valid signature was verified; False when the approval is
    unsigned and unsigned approvals are allowed. Raises ApprovalSignatureError
    otherwise. A signature that is present is always checked, even when not required."""
    if not approval.signature:
        if require_signed:
            raise ApprovalSignatureError("this deployment requires a signed approval")
        return False

    if approval.incident_id != decision_incident_id:
        raise ApprovalSignatureError("approval is for a different incident than the pending decision")

    public_key = public_keys.get(approval.approver_identity)
    message = approval_message(
        approval.incident_id, chosen_action, policy_rule_id, approval.decision, approval.timestamp
    )
    # Unknown approver and bad signature give the same answer: no identity probing.
    if public_key is None or not verify_signature(public_key, message, approval.signature):
        raise ApprovalSignatureError("approval signature could not be verified")

    current = now or datetime.now(UTC)
    stamp = approval.timestamp if approval.timestamp.tzinfo else approval.timestamp.replace(tzinfo=UTC)
    if abs((current - stamp).total_seconds()) > max_age_s:
        raise ApprovalSignatureError(f"approval timestamp is outside the allowed {max_age_s:.0f}s window")
    return True
