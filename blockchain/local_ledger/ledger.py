"""Hash-chained append-only local ledger.

A real ledger with real tamper detection, not a stub. Each block commits to
its predecessor's hash, so altering any committed record invalidates every
block after it and :meth:`verify_chain` identifies exactly where the chain
breaks.

WHAT THIS IS AND IS NOT
-----------------------
It **is**: append-only, content-addressed, integrity-verifiable, durable
(JSON-lines on disk), and usable in CI and on a laptop with no
infrastructure.

It is **not** a distributed ledger. There is no consensus, no Byzantine
fault tolerance, no independent validation by a second organisation, and a
party with write access to the file can rewrite the whole chain from
genesis. Those properties are exactly what Hyperledger Fabric provides and
this does not.

So the honest claim is: this backend demonstrates and tests the *provenance
integration* — that the right facts are committed at the right lifecycle
points, in the right shape, and that tampering is detectable — while Fabric
provides the *trust model*. Any paper using this backend must say which one
produced its numbers, and the evaluation labels every run with the backend
that generated it. See docs/blockchain.md.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.app.domain.ids import Clock, IdFactory, canonical_hash
from backend.app.domain.models import LedgerReceipt, ProvenanceRecord
from blockchain.adapter.interface import (
    LedgerError,
    LedgerIntegrityError,
    LedgerStats,
    ProvenanceLedger,
    VerificationResult,
)

#: Hash of the genesis block's predecessor. All-zero by convention.
GENESIS_PREVIOUS_HASH = "0" * 64


@dataclass
class LedgerBlock:
    """One committed block."""

    index: int
    provenance_id: str
    incident_id: str
    event_type: str
    committed_at: str
    submitting_org: str
    payload: dict[str, Any]
    previous_hash: str
    block_hash: str = ""

    def compute_hash(self) -> str:
        """Hash over everything except the hash field itself."""
        return canonical_hash(
            {
                "index": self.index,
                "provenance_id": self.provenance_id,
                "incident_id": self.incident_id,
                "event_type": self.event_type,
                "committed_at": self.committed_at,
                "submitting_org": self.submitting_org,
                "payload": self.payload,
                "previous_hash": self.previous_hash,
            }
        )

    def with_hash(self) -> LedgerBlock:
        block = LedgerBlock(**{**self.__dict__, "block_hash": ""})
        block.block_hash = block.compute_hash()
        return block

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> LedgerBlock:
        return cls(**json.loads(line))


@dataclass
class LocalProvenanceLedger(ProvenanceLedger):
    """File-backed hash-chained ledger."""

    path: Path
    ids: IdFactory
    clock: Clock
    #: When False, the ledger lives in memory only. Used by fast tests.
    persist: bool = True
    _blocks: list[LedgerBlock] = field(default_factory=list, init=False)
    _by_id: dict[str, LedgerBlock] = field(default_factory=dict, init=False)
    _latencies: list[float] = field(default_factory=list, init=False)

    backend_name = "local"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if self.persist:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        blocks: list[LedgerBlock] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    blocks.append(LedgerBlock.from_json(line))
                except (json.JSONDecodeError, TypeError) as exc:
                    raise LedgerIntegrityError(
                        f"{self.path}:{lineno} is not a valid ledger block: {exc}"
                    ) from exc
        self._blocks = blocks
        self._by_id = {b.provenance_id: b for b in blocks}

        # A ledger that fails verification on load must not be appended to:
        # doing so would build new blocks on a chain already known to be
        # broken and make the tampering harder to locate later.
        result = self.verify_chain()
        if not result.valid:
            raise LedgerIntegrityError(
                f"ledger at {self.path} failed integrity verification on load: "
                f"{result.detail}. Refusing to append to a broken chain."
            )

    def _append_line(self, block: LedgerBlock) -> None:
        if not self.persist:
            return
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(block.to_json() + "\n")

    # -- writing -----------------------------------------------------------
    def record(self, record: ProvenanceRecord) -> LedgerReceipt:
        started = time.perf_counter()
        payload = record.payload_for_ledger()
        self.validate_payload(payload)

        previous = self._blocks[-1].block_hash if self._blocks else GENESIS_PREVIOUS_HASH
        committed_at = self.clock.now()

        block = LedgerBlock(
            index=len(self._blocks),
            provenance_id=record.provenance_id,
            incident_id=record.incident_id,
            event_type=record.event_type.value,
            committed_at=committed_at.isoformat(),
            submitting_org=record.submitting_org,
            payload=payload,
            previous_hash=previous,
        ).with_hash()

        if block.provenance_id in self._by_id:
            raise LedgerError(
                f"provenance id {block.provenance_id} is already committed; "
                "an append-only ledger does not accept rewrites"
            )

        self._blocks.append(block)
        self._by_id[block.provenance_id] = block
        self._append_line(block)

        latency_ms = (time.perf_counter() - started) * 1000.0
        self._latencies.append(latency_ms)

        return LedgerReceipt(
            provenance_id=block.provenance_id,
            backend=self.backend_name,
            transaction_id=block.block_hash[:32],
            block_number=block.index,
            committed_at=committed_at,
            record_hash=block.block_hash,
            previous_hash=block.previous_hash,
            latency_ms=round(latency_ms, 4),
        )

    # -- reading -----------------------------------------------------------
    def get(self, provenance_id: str) -> dict[str, Any] | None:
        block = self._by_id.get(provenance_id)
        return dict(block.__dict__) if block else None

    def history(self, incident_id: str) -> list[dict[str, Any]]:
        return [dict(b.__dict__) for b in self._blocks if b.incident_id == incident_id]

    def all_blocks(self) -> list[dict[str, Any]]:
        return [dict(b.__dict__) for b in self._blocks]

    # -- verification ------------------------------------------------------
    def verify_chain(self) -> VerificationResult:
        started = time.perf_counter()
        broken: list[str] = []
        first_invalid: int | None = None

        expected_previous = GENESIS_PREVIOUS_HASH
        for i, block in enumerate(self._blocks):
            if block.index != i:
                broken.append(f"block {i}: index field is {block.index}")
                first_invalid = first_invalid if first_invalid is not None else i
            if block.previous_hash != expected_previous:
                broken.append(
                    f"block {i} ({block.provenance_id}): previous_hash "
                    f"{block.previous_hash[:12]} does not match the preceding "
                    f"block's hash {expected_previous[:12]}"
                )
                first_invalid = first_invalid if first_invalid is not None else i
            recomputed = block.with_hash().block_hash
            if recomputed != block.block_hash:
                broken.append(
                    f"block {i} ({block.provenance_id}): contents do not match "
                    f"its committed hash (expected {block.block_hash[:12]}, "
                    f"recomputed {recomputed[:12]}) - this block was altered "
                    "after commit"
                )
                first_invalid = first_invalid if first_invalid is not None else i
            expected_previous = block.block_hash

        elapsed = (time.perf_counter() - started) * 1000.0
        valid = not broken
        return VerificationResult(
            valid=valid,
            checked=len(self._blocks),
            first_invalid_index=first_invalid,
            detail=(
                f"{len(self._blocks)} blocks verified in {elapsed:.2f}ms"
                if valid
                else "; ".join(broken[:5])
            ),
            broken_links=broken,
        )

    def verify_evidence(self, provenance_id: str, evidence_hash: str) -> bool:
        block = self._by_id.get(provenance_id)
        if block is None:
            return False
        committed = str(block.payload.get("evidence_hash", ""))
        return bool(committed) and committed == evidence_hash

    # -- metrics -----------------------------------------------------------
    def stats(self) -> LedgerStats:
        started = time.perf_counter()
        self.verify_chain()
        verification_ms = (time.perf_counter() - started) * 1000.0

        sizes = [len(b.to_json().encode("utf-8")) for b in self._blocks]
        total = sum(sizes)
        latencies = sorted(self._latencies)
        p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0
        return LedgerStats(
            backend=self.backend_name,
            record_count=len(self._blocks),
            total_bytes=total,
            mean_latency_ms=round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
            p95_latency_ms=round(p95, 4),
            mean_record_bytes=round(total / len(sizes), 2) if sizes else 0.0,
            verification_ms=round(verification_ms, 4),
        )

    # -- test / experiment helpers ----------------------------------------
    def tamper_for_test(self, index: int, field_name: str, value: Any) -> None:
        """Alter a committed block in place, WITHOUT re-hashing.

        Exists so tests can prove tamper detection works. Any real write
        path goes through :meth:`record`, which always re-hashes, so this
        cannot be reached accidentally; the name makes misuse obvious in a
        diff.
        """
        block = self._blocks[index]
        if field_name in block.payload:
            block.payload[field_name] = value
        else:
            setattr(block, field_name, value)

    def reset(self) -> None:
        self._blocks.clear()
        self._by_id.clear()
        self._latencies.clear()
        if self.persist and self.path.exists():
            self.path.unlink()


__all__ = ["GENESIS_PREVIOUS_HASH", "LedgerBlock", "LocalProvenanceLedger"]
