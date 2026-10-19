import asyncio

from fastapi.testclient import TestClient

from app.blockchain.mock_fabric_client import MockFabricClient
from app.blockchain.outbox import OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.blockchain.policy_anchor import anchor_active_policy, policy_anchor_status
from app.core.app_factory import create_app
from app.core.config import Settings
from app.policy_engine.table import get_active_table
from app.schemas.enums import OutboxStatus


def test_anchor_is_queued_once_and_confirmed_by_the_worker():
    repo, client = OutboxRepository(), MockFabricClient()
    policy_hash = get_active_table().policy_hash
    assert policy_anchor_status(repo, policy_hash)["state"] == "not_queued"
    assert anchor_active_policy(repo) is True
    assert anchor_active_policy(repo) is False  # deduplicated while pending
    assert policy_anchor_status(repo, policy_hash)["state"] == OutboxStatus.PENDING.value
    asyncio.run(OutboxWorker(repo, client).process_once())
    status = policy_anchor_status(repo, policy_hash)
    assert status["state"] == OutboxStatus.CONFIRMED.value
    assert status["chain_tx_id"]
    assert asyncio.run(client.verify_policy(policy_hash)) is True
    assert anchor_active_policy(repo) is False  # confirmed also counts


def test_failed_anchor_is_queued_again():
    repo = OutboxRepository()
    assert anchor_active_policy(repo) is True
    repo.mark_failed(repo.list_all()[0].id, "ledger unreachable")
    assert anchor_active_policy(repo) is True
    assert len(repo.list_all()) == 2


def test_policy_endpoint_reports_not_queued_without_a_server_lifespan():
    client = TestClient(create_app(Settings()))
    assert client.get("/policy").json()["anchor"]["state"] == "not_queued"


def test_startup_queues_the_policy_and_the_audit_process_endpoint_confirms_it():
    with TestClient(create_app(Settings())) as client:
        assert client.get("/policy").json()["anchor"]["state"] == OutboxStatus.PENDING.value
        listed = client.get("/blockchain/audit")
        assert listed.status_code == 200
        assert any(e["record_type"] == "policy" for e in listed.json())
        assert client.post("/blockchain/audit/process").status_code == 200
        anchor = client.get("/policy").json()["anchor"]
        assert anchor["state"] == OutboxStatus.CONFIRMED.value
        assert anchor["chain_tx_id"]
