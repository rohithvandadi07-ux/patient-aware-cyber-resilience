"""Permissioned blockchain provenance.

Two backends behind one interface:

``local``
    A hash-chained append-only file ledger. Real integrity verification,
    runs anywhere, used by CI and the reproducible experiment suite. Not a
    distributed ledger: no consensus, no independent validation.

``fabric``
    Hyperledger Fabric via the Gateway API, with chaincode in
    ``fabric/chaincode/provenance``. Provides the trust model the local
    ledger cannot.

Which backend produced a given metric is recorded in every result, because
local-ledger latency is not Fabric latency and presenting one as the other
would be dishonest. See ``docs/blockchain.md``.
"""

from __future__ import annotations

import os
from pathlib import Path

from backend.app.domain.ids import Clock, IdFactory
from blockchain.adapter.fabric_gateway import (
    FabricConfig,
    FabricProvenanceLedger,
    connect_fabric,
)
from blockchain.adapter.interface import (
    FORBIDDEN_LEDGER_KEYS,
    MAX_RECORD_BYTES,
    LedgerError,
    LedgerIntegrityError,
    LedgerPayloadRejected,
    LedgerStats,
    ProvenanceLedger,
    VerificationResult,
)
from blockchain.local_ledger.ledger import LedgerBlock, LocalProvenanceLedger
from blockchain.service import ProvenanceService

DEFAULT_LOCAL_PATH = Path("data/local/provenance/ledger.jsonl")


def build_ledger(
    ids: IdFactory,
    clock: Clock,
    backend: str | None = None,
    path: str | Path | None = None,
    persist: bool = True,
) -> ProvenanceLedger:
    """Construct the configured provenance ledger.

    Defaults to ``local`` so the platform runs with no infrastructure and
    every experiment is reproducible without a Fabric deployment.
    """
    name = (backend or os.environ.get("PROVENANCE_BACKEND", "local")).lower()
    if name == "local":
        target = Path(
            path or os.environ.get("PROVENANCE_LOCAL_PATH", str(DEFAULT_LOCAL_PATH.parent))
        )
        if target.suffix != ".jsonl":
            target = target / "ledger.jsonl"
        return LocalProvenanceLedger(path=target, ids=ids, clock=clock, persist=persist)
    if name == "fabric":
        return connect_fabric(clock, FabricConfig.from_env())
    raise ValueError(f"unknown provenance backend {name!r}. Supported: local, fabric")


__all__ = [
    "DEFAULT_LOCAL_PATH",
    "FORBIDDEN_LEDGER_KEYS",
    "MAX_RECORD_BYTES",
    "FabricConfig",
    "FabricProvenanceLedger",
    "LedgerBlock",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerPayloadRejected",
    "LedgerStats",
    "LocalProvenanceLedger",
    "ProvenanceLedger",
    "ProvenanceService",
    "VerificationResult",
    "build_ledger",
]
