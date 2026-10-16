"""Genuine integration tests for the Postgres-backed repository
implementations (`Settings.repository_backend = "postgres"`,
`app/repositories/*.py` + `app/blockchain/outbox.py`'s `Postgres*` classes).

Exercises each `Postgres*` repository's full method surface against a REAL
Postgres database -- no mocks, no sqlite stand-in. Mirrors
`test_blockchain_integration.py`'s pattern: SKIPPED, not failed, when no
Postgres is actually reachable at `POSTGRES_TEST_URL` (default:
`postgresql+psycopg://postgres:postgres@localhost:5432/pacr_test`), since
that real infrastructure won't exist in every environment this repo is
cloned into. It has been run for real in this project's reference
environment -- see `docs/postgres-migration.md` for the verification
numbers -- this is not an assertion of untested code.

Run explicitly with:

    cd backend && python -m pytest tests/test_postgres_repositories.py -v

Each test truncates the tables it uses via each repository's own
`clear()`/`remove()`/`delete` methods (not a transaction rollback) so tests
can run in any order and repeated runs against the same database start
clean, the same discipline `TelemetryStore`'s and the in-memory
repositories' own tests already follow.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text

from app.blockchain.outbox import PostgresOutboxRepository
from app.core.db import (
    Base,
    build_session_factory,
    create_all_tables,
    create_hypertables,
    to_sync_url,
)
from app.models.orm import (
    AgentTraceORM,
    ExecutedResponseORM,
    IncidentORM,
    NetworkEventORM,
    OutboxEntryORM,
    ProposedResponseORM,
    RecoveryResultORM,
    TelemetryReadingORM,
)
from app.repositories.agent_traces import PostgresAgentTraceRecorder
from app.repositories.incidents import IncidentNotFoundError, PostgresIncidentRepository
from app.repositories.recovery_results import PostgresRecoveryResultRepository
from app.repositories.responses import (
    PostgresExecutedResponseRepository,
    PostgresProposedResponseRepository,
    ProposedResponseNotFoundError,
)
from app.repositories.telemetry_events import PostgresNetworkEventStore, PostgresTelemetryStore
from app.schemas.agents import RecoveryResult
from app.schemas.enums import IncidentStatus, OutboxRecordType, ResponseActionCategory
from app.schemas.events import NetworkEvent
from app.schemas.policy import PolicyDecision
from app.schemas.response import ExecutedResponse
from app.schemas.telemetry import TelemetryReading

POSTGRES_TEST_URL = os.environ.get(
    "POSTGRES_TEST_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/pacr_test"
)


def _postgres_reachable() -> bool:
    try:
        engine = create_engine(to_sync_url(POSTGRES_TEST_URL))
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_reachable(),
    reason=(
        f"no reachable Postgres at {POSTGRES_TEST_URL} -- this integration test needs a real "
        "database, not a mock; see app/core/db.py and docs/postgres-migration.md"
    ),
)


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(to_sync_url(POSTGRES_TEST_URL), future=True)
    # `create_all` never alters an existing table, so a test database left over
    # from an older schema (e.g. before `proposed_responses.alternatives`) would
    # fail with a missing-column error. This is a throwaway test database -- the
    # `session_factory` fixture below already deletes every row -- so rebuild it.
    Base.metadata.drop_all(eng)
    create_all_tables(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    factory = build_session_factory(engine)
    with engine.connect() as conn:
        for orm_class in (
            IncidentORM,
            AgentTraceORM,
            RecoveryResultORM,
            ProposedResponseORM,
            ExecutedResponseORM,
            OutboxEntryORM,
            NetworkEventORM,
            TelemetryReadingORM,
        ):
            conn.execute(text(f'DELETE FROM "{orm_class.__tablename__}"'))
        conn.commit()
    return factory


def test_incident_repository_create_get_update_list(session_factory):
    repo = PostgresIncidentRepository(session_factory)

    created = repo.create("INC-PG-1", "ventilator-01")
    assert created.incident_id == "INC-PG-1"
    assert created.status == IncidentStatus.DETECTED

    fetched = repo.get("INC-PG-1")
    assert fetched == created

    updated = repo.update_status("INC-PG-1", IncidentStatus.INVESTIGATING)
    assert updated.status == IncidentStatus.INVESTIGATING
    assert updated.updated_at >= created.updated_at

    with pytest.raises(IncidentNotFoundError):
        repo.get("does-not-exist")

    repo.create("INC-PG-2", "ventilator-01")
    repo.create("INC-PG-3", "infusion-pump-02")
    assert {i.incident_id for i in repo.list_for_device("ventilator-01")} == {"INC-PG-1", "INC-PG-2"}
    assert {i.incident_id for i in repo.list_all()} == {"INC-PG-1", "INC-PG-2", "INC-PG-3"}

    with pytest.raises(ValueError):
        repo.create("INC-PG-1", "ventilator-01")


def test_agent_trace_recorder_record_and_query(session_factory):
    recorder = PostgresAgentTraceRecorder(session_factory)

    ok = recorder.record_success("INC-PG-1", "threat_reasoning", {"in": 1}, {"out": 1})
    assert ok.succeeded is True
    assert ok.output_payload == {"out": 1}

    failed = recorder.record_failure("INC-PG-1", "risk_scoring", {"in": 2}, "boom")
    assert failed.succeeded is False
    assert failed.error == "boom"

    recorder.record_success("INC-PG-2", "threat_reasoning", {"in": 3}, {"out": 3})

    assert len(recorder.list_for_incident("INC-PG-1")) == 2
    assert len(recorder.list_for_agent("threat_reasoning")) == 2
    assert len(recorder.all_traces()) == 3


def test_recovery_result_repository_record_list_clear(session_factory):
    repo = PostgresRecoveryResultRepository(session_factory)

    repo.record(
        RecoveryResult(
            incident_id="INC-PG-1",
            response_id="RESP-1",
            containment_verified=True,
            residual_threats=["lingering-c2-beacon"],
            recovery_succeeded=True,
            reinvestigation_required=False,
        )
    )
    repo.record(
        RecoveryResult(
            incident_id="INC-PG-1",
            response_id="RESP-2",
            containment_verified=False,
            residual_threats=[],
            recovery_succeeded=False,
            reinvestigation_required=True,
        )
    )

    for_incident = repo.list_for_incident("INC-PG-1")
    assert len(for_incident) == 2
    assert for_incident[0].residual_threats == ["lingering-c2-beacon"]
    assert len(repo.list_all()) == 2

    repo.clear()
    assert repo.list_all() == []


def test_proposed_response_repository_put_replaces_not_accumulates(session_factory):
    repo = PostgresProposedResponseRepository(session_factory)

    decision = PolicyDecision(
        incident_id="INC-PG-1",
        chosen_action=ResponseActionCategory.ISOLATE_CRITICAL,
        requires_human_approval=True,
        policy_rule_id="rule-7",
        rationale="high risk score",
    )
    repo.put(decision)
    assert repo.get("INC-PG-1").policy_rule_id == "rule-7"

    replaced = decision.model_copy(update={"policy_rule_id": "rule-8"})
    repo.put(replaced)
    assert repo.get("INC-PG-1").policy_rule_id == "rule-8"
    assert len(repo.list_all()) == 1

    with pytest.raises(ProposedResponseNotFoundError):
        repo.get("does-not-exist")

    repo.remove("INC-PG-1")
    with pytest.raises(ProposedResponseNotFoundError):
        repo.get("INC-PG-1")
    repo.remove("INC-PG-1")  # no-op, not an error


def test_executed_response_repository_record_is_append_only(session_factory):
    repo = PostgresExecutedResponseRepository(session_factory)

    first = ExecutedResponse(
        incident_id="INC-PG-1",
        action_taken=ResponseActionCategory.ISOLATE_CRITICAL,
        executed_by="system",
        timestamp=datetime.now(UTC),
    )
    second = ExecutedResponse(
        incident_id="INC-PG-1",
        action_taken=ResponseActionCategory.ISOLATE_CRITICAL,
        executed_by="dr.chen",
        timestamp=datetime.now(UTC),
        chain_tx_id="0xabc123",
    )
    repo.record(first)
    repo.record(second)

    for_incident = repo.list_for_incident("INC-PG-1")
    assert len(for_incident) == 2
    assert for_incident[1].chain_tx_id == "0xabc123"
    assert len(repo.list_all()) == 2


def test_outbox_repository_full_lifecycle(session_factory):
    repo = PostgresOutboxRepository(session_factory)

    entry = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-PG-1", "x": 1})
    assert isinstance(entry.id, int)
    assert entry in repo.list_pending()
    assert repo.get(entry.id) == entry

    retried = repo.record_retry_attempt(entry.id, "transient network error")
    assert retried.attempts == 1
    assert retried.last_error == "transient network error"

    confirmed = repo.mark_confirmed(entry.id, "0xdeadbeef")
    assert confirmed.chain_tx_id == "0xdeadbeef"
    assert confirmed not in repo.list_pending()

    other = repo.enqueue(OutboxRecordType.DECISION, {"incident_id": "INC-PG-2"})
    failed = repo.mark_failed(other.id, "chaincode invocation failed")
    assert failed.status.value == "failed"

    assert len(repo.list_for_incident("INC-PG-1")) == 1
    assert len(repo.list_all()) == 2

    repo.clear()
    assert repo.list_all() == []


def test_app_factory_wires_postgres_backend_end_to_end(engine):
    """Not just unit-level: boots a real `create_app()` with
    `repository_backend='postgres'` and drives one incident through the
    actual `/incidents` API, proving the `app_factory.py` wiring (not just
    each repository class in isolation) works."""
    from fastapi.testclient import TestClient

    from app.core.app_factory import create_app
    from app.core.config import Settings

    settings = Settings(repository_backend="postgres", database_url=POSTGRES_TEST_URL)
    app = create_app(settings=settings)
    client = TestClient(app)

    with engine.connect() as conn:
        conn.execute(text('DELETE FROM "incidents"'))
        conn.commit()

    response = client.post(
        "/incidents",
        json={
            "incident_id": "INC-PG-E2E-1",
            "device_id": "ventilator-01",
            "attack_type": "mitm_injection",
            "evidence_ref": "evidence-ref-1",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "detected"

    fetched = client.get("/incidents/INC-PG-E2E-1")
    assert fetched.status_code == 200
    assert fetched.json()["device_id"] == "ventilator-01"


# --- time-series stores (events, telemetry) ----------------------------------

_T0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)


def _events():
    return [
        NetworkEvent(
            device_id="ventilator-01",
            timestamp=_T0 + timedelta(seconds=i * 5),
            event_type="spoofed_command" if i == 2 else "command_received",
            source="10.0.0.9",
            payload={"command": "set_tidal_volume", "value": str(i)},
            is_attack_injection=(i == 2),
        )
        for i in range(4)
    ] + [
        NetworkEvent(device_id="infusion-pump-01", timestamp=_T0, event_type="connection_attempt", source="x")
    ]


def test_network_event_store_roundtrip_filters_and_clear(session_factory):
    store = PostgresNetworkEventStore(session_factory)
    events = _events()
    store.record_many(events)

    assert store.query() == events  # insertion order, lossless (payload + injection flag included)
    vent = store.query("ventilator-01")
    assert [e.event_type for e in vent] == [
        "command_received",
        "command_received",
        "spoofed_command",
        "command_received",
    ]
    assert vent[2].is_attack_injection is True

    window = store.query("ventilator-01", since=_T0 + timedelta(seconds=5), until=_T0 + timedelta(seconds=10))
    assert [e.payload["value"] for e in window] == ["1", "2"]  # inclusive time range

    store.clear()
    assert store.query() == []


def test_telemetry_store_roundtrip_filters_and_clear(session_factory):
    store = PostgresTelemetryStore(session_factory)
    readings = [
        TelemetryReading(
            device_id="ecg-01", timestamp=_T0 + timedelta(seconds=i), readings={"heart_rate_bpm": 70.0 + i}
        )
        for i in range(3)
    ] + [TelemetryReading(device_id="ventilator-01", timestamp=_T0, readings={"tidal_volume_ml": 500.0})]
    store.record_many(readings)

    assert store.query() == readings
    assert [
        r.readings["heart_rate_bpm"] for r in store.query("ecg-01", since=_T0 + timedelta(seconds=1))
    ] == [71.0, 72.0]
    store.clear()
    assert store.query("ecg-01") == []


def test_hypertable_conversion_matches_what_the_database_supports(engine):
    status = create_hypertables(engine)
    assert set(status) == {"network_events", "telemetry_readings"}
    with engine.connect() as conn:
        has_timescale = conn.execute(
            text("SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'")
        ).first()
    if has_timescale:
        assert set(status.values()) == {"hypertable"}  # TimescaleDB present: must really convert
    else:
        # Plain Postgres: tables stay ordinary and the reason is reported, never silently ignored.
        assert all(v.startswith("plain: timescaledb extension is not installed") for v in status.values())


def test_full_app_on_postgres_persists_events_and_telemetry_across_app_instances(engine):
    from fastapi.testclient import TestClient

    from app.core.app_factory import create_app
    from app.core.config import Settings

    settings = Settings(repository_backend="postgres", database_url=POSTGRES_TEST_URL)
    first = create_app(settings)
    assert set(first.state.hypertable_status) == {"network_events", "telemetry_readings"}
    first.state.network_event_store.clear()
    first.state.network_event_store.record_many(_events())

    second = create_app(settings)  # a "restart": new app, same database
    client = TestClient(second)
    body = client.get("/events", params={"device_id": "ventilator-01"}).json()
    assert len(body) == 4 and any(e["is_attack_injection"] for e in body)
    second.state.network_event_store.clear()
