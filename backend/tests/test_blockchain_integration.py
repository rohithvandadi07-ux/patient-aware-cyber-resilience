"""Genuine end-to-end integration test for Phase 8 (architecture spec
Section 14): brings up the REAL native-Fabric network in
`blockchain/network/`, deploys the REAL chaincode from
`blockchain/chaincode/`, and exercises `SubprocessFabricClient` and
`OutboxWorker` against it for real -- no mocks, no Docker.

This is slow (network bring-up + first chaincode launch takes real wall
time) and depends on external infrastructure (Fabric binaries at
`FABRIC_BIN_DIR`, Node/npm reachable for the chaincode's `npm install`)
that won't exist in every environment this repo is cloned into. It is
SKIPPED, not failed, when `FABRIC_BIN_DIR` doesn't point at a real Fabric
binary release -- see `blockchain/network/README.md` for how to obtain
one. Run explicitly with:

    cd backend && python -m pytest tests/test_blockchain_integration.py -v

It is not part of the default fast unit-test loop other test files run in
(no live infrastructure dependency belongs there), but it has been run for
real in this project's reference environment -- this is not an assertion
of untested code.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from app.blockchain.fabric_client import SubprocessFabricClient
from app.blockchain.outbox import OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.schemas.enums import OutboxRecordType, OutboxStatus

REPO_ROOT = Path(__file__).resolve().parents[2]
NETWORK_SCRIPTS_DIR = REPO_ROOT / "blockchain" / "network" / "scripts"
CHAINCODE_DIR = REPO_ROOT / "blockchain" / "chaincode"
FABRIC_BIN_DIR = Path(os.environ.get("FABRIC_BIN_DIR", "/home/claude/fabric-dist"))
CHAINCODE_NAME = "provenance"
TS = "2026-10-12T00:00:00+00:00"

pytestmark = pytest.mark.skipif(
    not (FABRIC_BIN_DIR / "bin" / "peer").exists(),
    reason=(
        f"no native Fabric binaries at {FABRIC_BIN_DIR} -- see "
        "blockchain/network/README.md to obtain them; this integration test "
        "needs a real network, not a mock"
    ),
)


def _run(args: list[str], cwd: Path, timeout: int) -> None:
    result = subprocess.run(
        args, cwd=cwd, timeout=timeout, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed (exit {result.returncode}):\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


@pytest.fixture(scope="module")
def live_network(tmp_path_factory):
    """Resets, regenerates, and starts the real network, deploys the real
    chaincode, and tears everything down afterward. Module-scoped: every
    test in this file shares one network bring-up (each is still a
    separate, real chaincode invocation)."""
    _run(["./reset.sh"], cwd=NETWORK_SCRIPTS_DIR, timeout=60)
    _run(["./generate.sh"], cwd=NETWORK_SCRIPTS_DIR, timeout=60)
    _run(["./start-network.sh"], cwd=NETWORK_SCRIPTS_DIR, timeout=90)

    package_path = tmp_path_factory.mktemp("blockchain-integration") / "provenance.tgz"
    _run(
        ["./package-chaincode.sh", str(CHAINCODE_DIR), "provenance_1.0", str(package_path)],
        cwd=NETWORK_SCRIPTS_DIR,
        timeout=30,
    )
    _run(
        ["./deploy-chaincode.sh", str(package_path), CHAINCODE_NAME, "1.0", "1"],
        cwd=NETWORK_SCRIPTS_DIR,
        timeout=120,
    )

    try:
        yield NETWORK_SCRIPTS_DIR
    finally:
        _run(["./reset.sh"], cwd=NETWORK_SCRIPTS_DIR, timeout=60)


@pytest.fixture
def client(live_network) -> SubprocessFabricClient:
    return SubprocessFabricClient(network_scripts_dir=live_network, chaincode_name=CHAINCODE_NAME)


async def _wait_until_verified(client, evidence_hash: str, tries: int = 10, delay: float = 0.5) -> bool:
    """`query.sh` defaults to the Hospital peer; a `verify_evidence` query
    fired immediately after a write that committed is a REAL finding this
    integration test surfaced, distinct from the write-after-write
    endorsement race `TransientFabricError` already covers: a read against
    a peer that hasn't yet applied the just-committed block returns a
    successful, silent `false` -- there's no error to classify as
    transient, because nothing failed; the query is simply answered from
    state that hasn't caught up yet. `SubprocessFabricClient.verify_evidence`
    does not retry this on its own (a bare `false` is indistinguishable
    from a genuinely-absent hash), so callers that query right after a
    write -- including this test -- poll briefly instead of asserting on
    the first query. See claude/architecture-decisions.md for this finding
    alongside the endorsement-timing one.
    """
    for _ in range(tries):
        if await client.verify_evidence(evidence_hash):
            return True
        await asyncio.sleep(delay)
    return False


async def test_record_incident_commits_and_is_queryable(client):
    incident_id = "INT-TEST-INCIDENT"
    result = await client.record_incident(
        incident_id, "dev-infusion-pump-01", "ddos", "hash-evidence-integration", TS
    )

    assert result.tx_id
    assert result.payload["incidentId"] == incident_id
    assert await _wait_until_verified(client, "hash-evidence-integration") is True
    assert await client.verify_evidence("never-recorded-by-this-test") is False


async def test_recording_against_an_unknown_incident_raises(client):
    from app.blockchain.fabric_client import FabricInvocationError

    with pytest.raises(FabricInvocationError):
        await client.record_decision(
            "INT-TEST-NEVER-RECORDED", "hash-risk", "RULE-1", "isolate_critical"
        )


async def test_full_outbox_lifecycle_against_the_real_network(client):
    """Enqueues a full incident lifecycle (incident -> decision -> approval
    -> response -> recovery) in the Python outbox and drains it with
    OutboxWorker against the REAL client -- the same path a real deployment
    runs, not just the mock-client version already covered by
    app/blockchain/tests/test_outbox_worker.py. Also exercises the
    worker's transient-retry path for real: these calls are deliberately
    fired with no artificial delay between them, which is exactly the
    multi-org endorsement timing race documented in fabric_client.py and
    claude/architecture-decisions.md -- if the worker's retry logic didn't
    actually work, this test would fail or hang against the real network.
    """
    incident_id = "INT-TEST-LIFECYCLE"
    repo = OutboxRepository()
    worker = OutboxWorker(repo, client, max_attempts=8, base_backoff_seconds=0.5)

    repo.enqueue(
        OutboxRecordType.INCIDENT,
        {
            "incident_id": incident_id,
            "device_id": "dev-ventilator-02",
            "attack_type": "mitm_injection",
            "evidence_hash": "hash-evidence-lifecycle",
            "timestamp": TS,
        },
    )
    repo.enqueue(
        OutboxRecordType.DECISION,
        {
            "incident_id": incident_id,
            "risk_score_hash": "hash-risk-lifecycle",
            "policy_rule_id": "RULE-INTEGRATION-1",
            "recommended_action": "isolate_critical",
        },
    )
    repo.enqueue(
        OutboxRecordType.APPROVAL,
        {
            "incident_id": incident_id,
            "approver_identity": "soc-analyst-integration",
            "decision": "approved",
            "timestamp": TS,
        },
    )
    repo.enqueue(
        OutboxRecordType.RESPONSE,
        {
            "incident_id": incident_id,
            "action_taken": "isolate_critical",
            "executed_by": "orchestrator",
            "timestamp": TS,
        },
    )
    repo.enqueue(
        OutboxRecordType.RECOVERY,
        {
            "incident_id": incident_id,
            "recovery_verified": True,
            "residual_threats_hash": "hash-residual-lifecycle",
        },
    )

    # Drive process_once() in a bounded loop until every entry leaves
    # PENDING -- a transient entry stays PENDING across calls by design
    # (see OutboxWorker), so one call is not guaranteed to finish everything.
    for _ in range(20):
        if not repo.list_pending():
            break
        await worker.process_once()

    all_entries = [repo.get(i) for i in range(1, 6)]
    assert not repo.list_pending(), "outbox did not drain against the real network"
    assert all(e.status == OutboxStatus.CONFIRMED for e in all_entries), [
        (e.record_type, e.status, e.last_error) for e in all_entries
    ]
    assert all(e.chain_tx_id for e in all_entries)

    assert await _wait_until_verified(client, "hash-evidence-lifecycle") is True
    assert await _wait_until_verified(client, "hash-residual-lifecycle") is True
