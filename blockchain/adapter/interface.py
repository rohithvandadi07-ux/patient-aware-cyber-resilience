"""Provenance ledger interface.

Two implementations satisfy this: a Hyperledger Fabric gateway client and a
hash-chained local ledger. Both are real append-only ledgers with tamper
detection; they differ in consensus and in who can independently verify.

WHAT GOES ON THE LEDGER, AND WHY SO LITTLE
------------------------------------------
Only identifiers, hashes, verdicts and timestamps. Raw telemetry, logs,
evidence payloads, synthetic patient context and model artefacts stay
off-chain and are referenced by hash.

This is not a storage optimisation. A permissioned ledger is replicated to
every organisation on the channel and is, by design, immutable — so
anything written to it cannot be deleted, corrected, or kept from a peer
organisation. Putting patient context on such a ledger would be a serious
design error even with synthetic data, because the architecture would not
survive contact with real data. The hash-reference pattern means the ledger
proves *what was decided and that the evidence has not changed*, while the
evidence itself stays under ordinary access control.

:meth:`ProvenanceLedger.record` therefore accepts a
:class:`ProvenanceRecord`, whose ``payload_for_ledger()`` strips bulk
fields, and the local implementation asserts the absence of forbidden keys
rather than trusting the caller.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.app.domain.models import LedgerReceipt, ProvenanceRecord

#: Keys that must never appear in a ledger payload. Checked on every write.
FORBIDDEN_LEDGER_KEYS: frozenset[str] = frozenset(
    {
        "payload",
        "patient",
        "patient_ref",
        "telemetry",
        "events",
        "measurements",
        "raw",
        "evidence_payload",
        "model_artifact",
        "feature_matrix",
        "synthetic_patient_context",
    }
)

#: Maximum serialised size of a single ledger record, in bytes. A record
#: that exceeds this is almost certainly carrying bulk data that belongs
#: off-chain, so the write is refused rather than silently bloating the
#: chain on every peer.
MAX_RECORD_BYTES = 4096


class LedgerError(Exception):
    """A ledger operation failed."""


class LedgerPayloadRejected(LedgerError):
    """The payload carried data that must not go on-chain.

    Raised rather than filtered: silently dropping a forbidden field would
    hide a design error in the calling code, and the next field added might
    not be on the deny list.
    """


class LedgerIntegrityError(LedgerError):
    """The ledger's own chain failed verification. Tampering or corruption."""


@dataclass
class VerificationResult:
    """Outcome of verifying a record or the whole chain."""

    valid: bool
    checked: int
    first_invalid_index: int | None = None
    detail: str = ""
    broken_links: list[str] = field(default_factory=list)


@dataclass
class LedgerStats:
    """Metrics the evaluation framework reports for the blockchain pillar."""

    backend: str
    record_count: int
    total_bytes: int
    mean_latency_ms: float
    p95_latency_ms: float
    mean_record_bytes: float
    verification_ms: float | None = None

    @property
    def storage_overhead_bytes_per_record(self) -> float:
        return self.total_bytes / self.record_count if self.record_count else 0.0


class ProvenanceLedger(ABC):
    """Append-only provenance ledger."""

    backend_name: str = "abstract"

    @abstractmethod
    def record(self, record: ProvenanceRecord) -> LedgerReceipt:
        """Append one provenance record and return a commit receipt."""

    @abstractmethod
    def get(self, provenance_id: str) -> dict[str, Any] | None:
        """Retrieve a committed record by id."""

    @abstractmethod
    def history(self, incident_id: str) -> list[dict[str, Any]]:
        """All committed records for one incident, in commit order."""

    @abstractmethod
    def verify_chain(self) -> VerificationResult:
        """Verify the ledger's internal integrity."""

    @abstractmethod
    def verify_evidence(self, provenance_id: str, evidence_hash: str) -> bool:
        """Check a claimed evidence hash against the committed record.

        Backs the specification's ``verifyEvidence``. Returns False when the
        record does not exist, so a caller cannot read a missing record as
        a pass.
        """

    @abstractmethod
    def stats(self) -> LedgerStats:
        """Latency, throughput and storage metrics for this ledger."""

    # -- shared validation -------------------------------------------------
    @staticmethod
    def validate_payload(payload: dict[str, Any]) -> None:
        """Reject anything that must not be committed. Called by every write."""
        import json

        offending = sorted(set(payload) & FORBIDDEN_LEDGER_KEYS)
        if offending:
            raise LedgerPayloadRejected(
                f"ledger payload contains forbidden keys {offending}. Raw "
                "telemetry, evidence payloads and patient context must stay "
                "off-chain and be referenced by hash: a permissioned ledger is "
                "replicated to every organisation and is immutable, so such "
                "data could never be deleted or withheld. "
                "See blockchain/adapter/interface.py."
            )
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > MAX_RECORD_BYTES:
            raise LedgerPayloadRejected(
                f"ledger record is {len(encoded)} bytes, above the "
                f"{MAX_RECORD_BYTES}-byte limit. A record this large is almost "
                "certainly carrying bulk data that belongs off-chain."
            )

    def close(self) -> None:  # noqa: B027 - optional for implementations
        """Release resources. Optional."""


__all__ = [
    "FORBIDDEN_LEDGER_KEYS",
    "MAX_RECORD_BYTES",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerPayloadRejected",
    "LedgerStats",
    "ProvenanceLedger",
    "VerificationResult",
]
