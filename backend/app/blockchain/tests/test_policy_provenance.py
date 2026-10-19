import asyncio
from datetime import UTC, datetime

import pytest

from app.blockchain.fabric_client import FabricInvocationError
from app.blockchain.mock_fabric_client import MockFabricClient
from app.blockchain.outbox import OutboxRepository, enqueue_policy
from app.blockchain.outbox_worker import OutboxWorker
from app.schemas.blockchain import PolicyProvenance

HASH = "ab" * 32
TS = "2026-10-19T10:00:00Z"


def run(coro):
    return asyncio.run(coro)


def test_mock_records_and_verifies_a_policy():
    client = MockFabricClient()
    assert run(client.verify_policy(HASH)) is False
    result = run(client.record_policy(HASH, "pacr-default-policy", "1", TS))
    assert result.payload["policyHash"] == HASH
    assert run(client.verify_policy(HASH)) is True


def test_mock_record_policy_is_idempotent():
    client = MockFabricClient()
    first = run(client.record_policy(HASH, "pacr-default-policy", "1", TS))
    second = run(client.record_policy(HASH, "renamed", "2", "2027-01-01T00:00:00Z"))
    assert second.payload == first.payload


@pytest.mark.parametrize("bad", ["", "not-a-hash", "AB" * 32, "ab" * 31])
def test_mock_rejects_a_malformed_policy_hash(bad):
    with pytest.raises(FabricInvocationError):
        run(MockFabricClient().record_policy(bad, "n", "1", TS))


def test_worker_commits_a_policy_outbox_entry():
    repo = OutboxRepository()
    client = MockFabricClient()
    entry = enqueue_policy(
        repo,
        PolicyProvenance(
            policy_hash=HASH,
            policy_name="pacr-default-policy",
            policy_version=1,
            timestamp=datetime(2026, 10, 19, 10, 0, tzinfo=UTC),
        ),
    )
    processed = run(OutboxWorker(repo, client).process_once())
    assert [e.id for e in processed] == [entry.id]
    assert repo.get(entry.id).chain_tx_id is not None
    assert repo.list_pending() == []
    assert run(client.verify_policy(HASH)) is True
