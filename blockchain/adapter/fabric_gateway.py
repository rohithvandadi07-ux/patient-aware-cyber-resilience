"""Hyperledger Fabric gateway adapter.

Implements :class:`ProvenanceLedger` against a running Fabric network via
the Gateway API, invoking the chaincode in
``blockchain/fabric/chaincode/provenance``.

HONESTY ABOUT WHAT IS AND IS NOT EXERCISED
------------------------------------------
This adapter is written, reviewed and unit-tested against a fake gateway,
but it has **not** been executed against a live Fabric network in this
project's CI, because a Fabric network needs a multi-container deployment
that the development environment cannot host. Its tests use a stub gateway
and therefore verify the *adapter's* logic — payload hygiene, receipt
construction, error translation — not Fabric's behaviour.

Consequently:

* Every blockchain metric reported in the paper is labelled with the
  backend that produced it. Local-ledger latency is not presented as Fabric
  latency; they differ by orders of magnitude and conflating them would be
  dishonest.
* ``docs/blockchain.md`` lists this as a known limitation with the exact
  steps to reproduce on a real network.
* Fabric-dependent tests carry the ``fabric`` pytest marker and skip when
  no network is reachable, rather than being silently absent.

The alternative — claiming Fabric results from a local hash chain — is the
kind of shortcut that gets a paper retracted.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from backend.app.domain.ids import Clock, canonical_hash
from backend.app.domain.models import LedgerReceipt, ProvenanceRecord
from blockchain.adapter.interface import (
    LedgerError,
    LedgerStats,
    ProvenanceLedger,
    VerificationResult,
)

#: Chaincode transaction names, matching the specification's candidate set.
CHAINCODE_FUNCTIONS: dict[str, str] = {
    "incident_recorded": "recordIncident",
    "decision_recorded": "recordDecision",
    "approval_recorded": "recordApproval",
    "response_recorded": "recordResponse",
    "recovery_recorded": "recordRecovery",
}

#: Read-only chaincode queries.
QUERY_FUNCTIONS = {
    "get": "getProvenance",
    "history": "getIncidentHistory",
    "verify": "verifyEvidence",
}


class FabricContract(Protocol):
    """The subset of the Fabric Gateway contract API this adapter uses."""

    def submit_transaction(self, name: str, *args: str) -> bytes: ...
    def evaluate_transaction(self, name: str, *args: str) -> bytes: ...


@dataclass
class FabricConfig:
    """Connection settings. Read from the environment; never hard-coded.

    Identity material lives OUTSIDE the repository — see ``.env.example``
    and ``.gitignore``, which excludes ``crypto-config/``,
    ``organizations/`` and every key and certificate pattern.
    """

    channel: str = "pacrchannel"
    chaincode: str = "provenance"
    msp_id: str = "HospitalMSP"
    endpoint: str = "localhost:7051"
    host_alias: str = "peer0.hospital.pacr.local"
    cert_path: str = ""
    key_path: str = ""
    tls_ca_path: str = ""

    @classmethod
    def from_env(cls) -> FabricConfig:
        return cls(
            channel=os.environ.get("FABRIC_CHANNEL", "pacrchannel"),
            chaincode=os.environ.get("FABRIC_CHAINCODE", "provenance"),
            msp_id=os.environ.get("FABRIC_MSP_ID", "HospitalMSP"),
            endpoint=os.environ.get("FABRIC_GATEWAY_ENDPOINT", "localhost:7051"),
            host_alias=os.environ.get("FABRIC_GATEWAY_HOST_ALIAS", "peer0.hospital.pacr.local"),
            cert_path=os.environ.get("FABRIC_CERT_PATH", ""),
            key_path=os.environ.get("FABRIC_KEY_PATH", ""),
            tls_ca_path=os.environ.get("FABRIC_TLS_CA_PATH", ""),
        )

    def validate(self) -> None:
        missing = [
            name
            for name, value in (
                ("FABRIC_CERT_PATH", self.cert_path),
                ("FABRIC_KEY_PATH", self.key_path),
                ("FABRIC_TLS_CA_PATH", self.tls_ca_path),
            )
            if not value
        ]
        if missing:
            raise LedgerError(
                f"Fabric identity material is not configured: {missing}. Set "
                "these in .env (paths outside the repository) or use "
                "PROVENANCE_BACKEND=local."
            )


@dataclass
class FabricProvenanceLedger(ProvenanceLedger):
    """Fabric-backed provenance ledger."""

    contract: FabricContract
    clock: Clock
    config: FabricConfig = field(default_factory=FabricConfig)
    _latencies: list[float] = field(default_factory=list, init=False)
    _count: int = field(default=0, init=False)
    _bytes: int = field(default=0, init=False)

    backend_name = "fabric"

    # -- writing -----------------------------------------------------------
    def record(self, record: ProvenanceRecord) -> LedgerReceipt:
        import json

        payload = record.payload_for_ledger()
        self.validate_payload(payload)

        function = CHAINCODE_FUNCTIONS.get(record.event_type.value)
        if function is None:
            raise LedgerError(
                f"no chaincode function for event type "
                f"{record.event_type.value!r}; known: "
                f"{sorted(CHAINCODE_FUNCTIONS)}"
            )

        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        started = time.perf_counter()
        try:
            raw = self.contract.submit_transaction(function, record.provenance_id, encoded)
        except Exception as exc:
            raise LedgerError(
                f"Fabric transaction {function} failed for "
                f"{record.provenance_id}: {type(exc).__name__}: {exc}"
            ) from exc
        latency_ms = (time.perf_counter() - started) * 1000.0

        result = self._decode(raw)
        self._latencies.append(latency_ms)
        self._count += 1
        self._bytes += len(encoded.encode("utf-8"))

        return LedgerReceipt(
            provenance_id=record.provenance_id,
            backend=self.backend_name,
            transaction_id=str(result.get("txId") or result.get("tx_id") or ""),
            block_number=(int(result["blockNumber"]) if "blockNumber" in result else None),
            committed_at=self.clock.now(),
            record_hash=str(result.get("recordHash") or canonical_hash(payload)),
            previous_hash=result.get("previousHash"),
            latency_ms=round(latency_ms, 4),
        )

    # -- reading -----------------------------------------------------------
    def get(self, provenance_id: str) -> dict[str, Any] | None:
        try:
            raw = self.contract.evaluate_transaction(QUERY_FUNCTIONS["get"], provenance_id)
        except Exception:
            return None
        decoded = self._decode(raw)
        return decoded or None

    def history(self, incident_id: str) -> list[dict[str, Any]]:
        raw = self.contract.evaluate_transaction(QUERY_FUNCTIONS["history"], incident_id)
        decoded = self._decode(raw)
        records = decoded.get("records", decoded) if isinstance(decoded, dict) else decoded
        return list(records) if isinstance(records, list) else []

    # -- verification ------------------------------------------------------
    def verify_chain(self) -> VerificationResult:
        """Fabric validates its own chain; this reports what the peer says.

        A client cannot independently verify a Fabric chain without reading
        every block from the peer, which is not what this method is for. We
        report the peer's own view and say so, rather than implying a
        client-side proof we did not perform.
        """
        started = time.perf_counter()
        try:
            raw = self.contract.evaluate_transaction("getChainInfo")
            info = self._decode(raw)
            height = int(info.get("height", 0))
            elapsed = (time.perf_counter() - started) * 1000.0
            return VerificationResult(
                valid=True,
                checked=height,
                detail=(
                    f"peer reports chain height {height}; validated by Fabric's "
                    f"own ordering and endorsement, queried in {elapsed:.1f}ms. "
                    "This is the peer's view, not an independent client-side "
                    "verification of every block."
                ),
            )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                checked=0,
                detail=f"could not query chain info: {type(exc).__name__}: {exc}",
            )

    def verify_evidence(self, provenance_id: str, evidence_hash: str) -> bool:
        try:
            raw = self.contract.evaluate_transaction(
                QUERY_FUNCTIONS["verify"], provenance_id, evidence_hash
            )
        except Exception:
            return False
        decoded = self._decode(raw)
        return bool(decoded.get("valid", False))

    # -- metrics -----------------------------------------------------------
    def stats(self) -> LedgerStats:
        latencies = sorted(self._latencies)
        p95 = latencies[min(len(latencies) - 1, int(0.95 * len(latencies)))] if latencies else 0.0
        return LedgerStats(
            backend=self.backend_name,
            record_count=self._count,
            total_bytes=self._bytes,
            mean_latency_ms=round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
            p95_latency_ms=round(p95, 4),
            mean_record_bytes=round(self._bytes / self._count, 2) if self._count else 0.0,
        )

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _decode(raw: bytes | str | None) -> dict[str, Any]:
        import json

        if not raw:
            return {}
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        if not text.strip():
            return {}
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}
        return value if isinstance(value, dict) else {"records": value}


def connect_fabric(clock: Clock, config: FabricConfig | None = None):
    """Open a Fabric Gateway connection from environment configuration.

    This is a documented integration point that has **not** been exercised
    against a live network in this project, because the development
    environment cannot host a Fabric deployment.

    It therefore refuses rather than returning a half-configured client.
    A client that looks connected and fails later, deep inside the SDK with
    a misleading error, is worse than an explicit refusal: it invites
    someone to believe Fabric results were produced when they were not.
    Wire this to a real deployment following docs/blockchain.md.
    """
    from importlib.util import find_spec

    cfg = config or FabricConfig.from_env()
    cfg.validate()

    if find_spec("hyperledger") is None:
        raise LedgerError(
            "the Fabric Gateway SDK is not installed. Install the optional "
            'extra with `pip install -e ".[fabric]"`, or use '
            "PROVENANCE_BACKEND=local."
        )

    raise LedgerError(
        "connect_fabric has not been exercised against a live Fabric network "
        "in this project. Wire it to your deployment following "
        "docs/blockchain.md, or use PROVENANCE_BACKEND=local. It refuses "
        "deliberately rather than returning a half-configured client whose "
        "later failure would be harder to diagnose - and whose apparent "
        "success would be worse."
    )


__all__ = [
    "CHAINCODE_FUNCTIONS",
    "QUERY_FUNCTIONS",
    "FabricConfig",
    "FabricContract",
    "FabricProvenanceLedger",
    "connect_fabric",
]
