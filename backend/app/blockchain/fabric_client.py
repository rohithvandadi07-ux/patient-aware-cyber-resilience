"""L9 -- Fabric client: the boundary between this backend and the chaincode
in `blockchain/chaincode/` running on the network in `blockchain/network/`.

`FabricClient` is a `Protocol` with one method per chaincode operation
(architecture spec Section 14), so the outbox worker (`outbox_worker.py`)
never depends on *how* a transaction actually reaches the ledger.
`SubprocessFabricClient` is the real implementation: this backend has no
Fabric Go SDK or Node SDK binding, so it shells out to the same
`invoke.sh`/`query.sh` scripts a human operator would run by hand (see
`blockchain/network/README.md`) -- not a shortcut, but the same interface
this project already proved end-to-end in Phase 8's spike and real-script
verification. `MockFabricClient` is a test double that mirrors the
chaincode's own validation rules (write-once incident, append-only
decision/approval/response/recovery, evidence-hash index) in Python, so
outbox-worker tests can assert real behavior without a live network.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


class FabricInvocationError(Exception):
    """A chaincode invocation failed, and is not expected to succeed on retry
    without some other change (bad arguments, a business-rule rejection from
    the chaincode itself, etc.)."""


class TransientFabricError(FabricInvocationError):
    """A chaincode invocation failed in a way this project has observed to
    be a timing artifact, not a real rejection -- specifically, the
    multi-org endorsement race documented in the project's architecture
    decisions doc: a peer's own world state hasn't yet caught up to a
    just-committed prior transaction for the same incident_id when the next
    transaction's proposal is simulated on it. Retrying after a short delay
    resolved this every time it was observed by hand. The outbox worker
    retries this specific error type with backoff; it does NOT retry a
    plain `FabricInvocationError`, since that's the chaincode correctly
    rejecting bad input or an out-of-order call.
    """


# Matches the family of Fabric endorsement-failure messages this project
# has actually seen be transient (see TransientFabricError's docstring).
# Deliberately narrow -- a message that doesn't match this is treated as a
# real, non-retryable rejection rather than guessed to be transient.
_TRANSIENT_ERROR_PATTERN = re.compile(
    r"endorsement failure.*has no recordIncident entry", re.IGNORECASE | re.DOTALL
)


@dataclass(frozen=True)
class FabricTxResult:
    """What a successful chaincode invocation returns: the committed
    transaction ID (goes into the off-chain record's `chain_tx_id` column)
    and the chaincode's own JSON return payload, parsed."""

    tx_id: str
    payload: dict = field(default_factory=dict)


class FabricClient(Protocol):
    """One method per chaincode operation (architecture spec Section 14).
    Every record_* method returns the committed `FabricTxResult`;
    `verify_evidence` is a query, not a transaction, and returns a bool.

    Arguments are the already-stringified/normalized values the chaincode
    expects (see `blockchain/chaincode/README.md`'s argument table) --
    converting an off-chain Pydantic model (`app/schemas/blockchain.py`)
    into these is the outbox worker's job, not this client's.
    """

    async def record_incident(
        self, incident_id: str, device_id: str, attack_type: str, evidence_hash: str, timestamp: str
    ) -> FabricTxResult: ...

    async def record_decision(
        self, incident_id: str, risk_score_hash: str, policy_rule_id: str, recommended_action: str
    ) -> FabricTxResult: ...

    async def record_approval(
        self, incident_id: str, approver_identity: str, decision: str, timestamp: str
    ) -> FabricTxResult: ...

    async def record_response(
        self, incident_id: str, action_taken: str, executed_by: str, timestamp: str
    ) -> FabricTxResult: ...

    async def record_recovery(
        self, incident_id: str, recovery_verified: bool, residual_threats_hash: str | None
    ) -> FabricTxResult: ...

    async def verify_evidence(self, evidence_hash: str) -> bool: ...


class SubprocessFabricClient:
    """Real `FabricClient`, implemented by shelling out to
    `blockchain/network/scripts/invoke.sh`/`query.sh`.

    This is a deliberate choice, not a stopgap: this project's Fabric
    network runs from native binaries with no Docker (see
    `blockchain/network/README.md`), and there is no Fabric Go/Node SDK
    dependency anywhere else in this Python backend. The shell scripts are
    the same interface a human operator uses, already proven end-to-end
    (Phase 8 spike, then again against the real committed scripts and real
    chaincode) -- wrapping them is less new surface area than embedding a
    gRPC-based Fabric SDK client for a single consumer.
    """

    def __init__(self, network_scripts_dir: Path, chaincode_name: str) -> None:
        self._scripts_dir = network_scripts_dir
        self._chaincode_name = chaincode_name

    async def record_incident(
        self, incident_id: str, device_id: str, attack_type: str, evidence_hash: str, timestamp: str
    ) -> FabricTxResult:
        return await self._invoke(
            "recordIncident", [incident_id, device_id, attack_type, evidence_hash, timestamp]
        )

    async def record_decision(
        self, incident_id: str, risk_score_hash: str, policy_rule_id: str, recommended_action: str
    ) -> FabricTxResult:
        return await self._invoke(
            "recordDecision", [incident_id, risk_score_hash, policy_rule_id, recommended_action]
        )

    async def record_approval(
        self, incident_id: str, approver_identity: str, decision: str, timestamp: str
    ) -> FabricTxResult:
        return await self._invoke(
            "recordApproval", [incident_id, approver_identity, decision, timestamp]
        )

    async def record_response(
        self, incident_id: str, action_taken: str, executed_by: str, timestamp: str
    ) -> FabricTxResult:
        return await self._invoke(
            "recordResponse", [incident_id, action_taken, executed_by, timestamp]
        )

    async def record_recovery(
        self, incident_id: str, recovery_verified: bool, residual_threats_hash: str | None
    ) -> FabricTxResult:
        # Chaincode args are always strings; "" is this contract's own
        # convention for "no residual_threats_hash provided" (see
        # blockchain/chaincode/README.md) -- there is no native null for a
        # chaincode string arg.
        return await self._invoke(
            "recordRecovery",
            [incident_id, "true" if recovery_verified else "false", residual_threats_hash or ""],
        )

    async def verify_evidence(self, evidence_hash: str) -> bool:
        args = _args_json(["verifyEvidence", evidence_hash])
        stdout, _ = await self._run_script("query.sh", [self._chaincode_name, args])
        return stdout.strip() == "true"

    async def _invoke(self, function_name: str, args: list[str]) -> FabricTxResult:
        stdout, stderr = await self._run_script(
            "invoke.sh", [self._chaincode_name, _args_json([function_name, *args])]
        )
        return _parse_invoke_result(stdout + stderr)

    async def _run_script(self, script_name: str, args: list[str]) -> tuple[str, str]:
        process = await asyncio.create_subprocess_exec(
            str(self._scripts_dir / script_name),
            *args,
            cwd=self._scripts_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        if process.returncode != 0:
            combined = (stdout + stderr).strip()
            if _TRANSIENT_ERROR_PATTERN.search(combined):
                raise TransientFabricError(combined)
            raise FabricInvocationError(combined or f"{script_name} exited {process.returncode}")
        return stdout, stderr


def _args_json(args: list[str]) -> str:
    return json.dumps({"Args": args})


# Matches `peer chaincode invoke`'s own log line, e.g.:
#   Chaincode invoke successful. result: status:200 payload:"{\"incidentId\":...}"
_INVOKE_RESULT_PATTERN = re.compile(r'payload:"((?:[^"\\]|\\.)*)"')
_TXID_PATTERN = re.compile(r"txid \[([0-9a-f]+)\]")


def _parse_invoke_result(combined_output: str) -> FabricTxResult:
    payload: dict = {}
    payload_match = _INVOKE_RESULT_PATTERN.search(combined_output)
    if payload_match:
        raw_payload = payload_match.group(1).encode().decode("unicode_escape")
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            payload = {}

    tx_id = payload.get("recordedTxId")
    if not tx_id:
        txid_match = _TXID_PATTERN.search(combined_output)
        tx_id = txid_match.group(1) if txid_match else ""
    return FabricTxResult(tx_id=tx_id, payload=payload)
