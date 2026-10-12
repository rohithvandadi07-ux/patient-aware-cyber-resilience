"""Canonical hashing for blockchain provenance payloads.

Architecture spec Section 14: "Only hashes and structured metadata -- never
raw telemetry, logs, or patient identifiers cross into these models"
(`app/schemas/blockchain.py`'s module docstring). Every `*Provenance` schema
and `FabricClient` method takes an already-computed hash string
(`evidence_hash`, `risk_score_hash`, `residual_threats_hash`) -- nothing
before Phase 9 actually computed one from a real object; every test so far
passed a literal placeholder string like `"hash-evidence-integration"`
(see `backend/tests/test_blockchain_integration.py`).

This module is that real computation: a stable SHA-256 hex digest over a
canonical JSON encoding of whatever evidence is being committed (a Pydantic
model, a plain dict/list, or a bare string). "Canonical" here means
`sort_keys=True` -- so the same logical evidence hashes identically
regardless of field insertion order -- and `default=str` so non-JSON-native
values (datetimes, enums already handled by `model_dump(mode="json")`)
never raise. This is a one-way hash for provenance/integrity comparison, not
a security credential -- it is deliberately not salted or keyed, matching
`verifyEvidence`'s own equality-based lookup in
`blockchain/chaincode/lib/provenanceContract.js`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def hash_payload(payload: BaseModel | dict[str, Any] | list[Any] | str) -> str:
    """Return a stable SHA-256 hex digest for `payload`.

    A `BaseModel` is dumped via `model_dump(mode="json")` first, so datetimes
    and enums are already JSON-native before encoding. A bare string is
    hashed as-is (no re-encoding), which is what lets a caller hash a single
    evidence reference (e.g. `DetectionEvent.evidence_ref`) without wrapping
    it in a structure first.
    """
    if isinstance(payload, BaseModel):
        data: Any = payload.model_dump(mode="json")
    else:
        data = payload

    canonical = data if isinstance(data, str) else json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
