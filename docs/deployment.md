# Deployment guide

Three ways to bring this stack up, in increasing order of completeness, all
based on what the real `docker-compose.yml`, `.env.example`,
`backend/Dockerfile`, and `frontend/Dockerfile` actually specify today — not
an aspirational target. Read `docker-compose.yml`'s own header comment and
`README.md`'s "Docker" section too; this file restates and organizes that
disclosure, it doesn't supersede it.

## 0. The one fact that matters before anything else

**Nothing in this project's Docker setup has ever been build- or
run-verified inside this project's own development sandbox**, because that
sandbox's network policy blocks every container registry it was tried
against (Docker Hub, ghcr.io, mcr.microsoft.com, gcr.io all returned 403
Forbidden — confirmed by actually trying to pull `python:3.12-slim` for
`backend/Dockerfile`). What has been checked without needing a registry:
`docker compose config` parses and interpolates `docker-compose.yml`
cleanly. This is a constraint of *this project's own dev history*, not a
claim that Docker is blocked for you — if your environment has normal
registry access, `docker compose up --build` should work as described
below, but verify it there; it has not been proven to work end-to-end
anywhere yet.

## 1. Local development (no Docker)

What every phase's own test suite actually runs against.

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example ../.env   # adjust as needed
pytest                        # 366 tests collected as of this writing
ruff check app                # lint
uvicorn app.main:app --reload --port 8000
```

```bash
# Frontend, in a second terminal
cd frontend
npm install
npm run test     # Vitest + React Testing Library
npm run lint      # oxlint
npm run build     # tsc -b && vite build
npm run dev       # Vite dev server, http://localhost:5173
```

The backend's default CORS allowlist already includes the Vite dev
server's default origin (`Settings.cors_allowed_origins`), so no CORS
configuration is needed for this path.

Repository backend defaults to **in-memory** (`REPOSITORY_BACKEND` unset or
`memory`) — every repository behind every router is a plain Python `dict`.
State does not survive a process restart. This is the backend every unit
and integration test in the suite actually runs against; it needs nothing
else running.

### Running the Phase 11 end-to-end suite

```bash
cd backend && source .venv/bin/activate
playwright install chromium   # once, if not already installed
pytest -c ../tests/pytest.ini ../tests/e2e
```

This starts its own backend and frontend processes — it does not need
either already running. See `tests/README.md` for exactly what it proves.

## 2. Opt-in Postgres backend (still no Docker)

A real, scope-limited Postgres migration landed post-Phase-15:
`incidents`, `agent_traces`, `recovery_results`, `proposed_responses`,
`executed_responses`, and `outbox_entries` have real `Postgres*` repository
implementations (`backend/app/models/orm.py`, `backend/app/repositories/
*.py`), selected by `Settings.repository_backend`.

```bash
# Install and start Postgres 16 natively (this project's own verification
# used this path, not Docker, for the same registry-block reason as above)
# e.g. on Debian/Ubuntu:
sudo apt-get install postgresql-16
sudo systemctl start postgresql

# Create the dev database/role matching .env.example's defaults, or set
# your own and update DATABASE_URL to match
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres';"
createdb -U postgres patient_aware_cyber_resilience

cd backend && source .venv/bin/activate
export REPOSITORY_BACKEND=postgres
export DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/patient_aware_cyber_resilience
python -c "
from app.core.config import Settings
from app.core.db import build_engine, create_all_tables, to_sync_url
s = Settings()
engine = build_engine(s.database_url)
create_all_tables(engine)
print('tables created against', to_sync_url(s.database_url))
"
uvicorn app.main:app --reload
```

**Important, real caveats, not hidden:**

- There is no migration tool (no Alembic) — `create_all_tables` only
  creates tables that don't already exist; it never alters an existing
  table's columns. Schema changes need a manual `DROP`/recreate in dev.
- The driver is **sync** (`psycopg`, not `asyncpg`), by deliberate choice
  (`backend/app/core/db.py`'s own docstring) — a blocking DB call inside an
  `async def` route handler blocks that worker's event loop for the call's
  duration. Acceptable for this research prototype's actual scale (one
  simulated three-device hospital), not for a high-concurrency deployment.
- `NetworkEventStore`/`TelemetryStore` (network events and device
  telemetry) **are** covered when `REPOSITORY_BACKEND=postgres`: tables
  `network_events` / `telemetry_readings`, converted to TimescaleDB
  hypertables on startup if the `timescaledb` extension is available (the
  Compose `db` service image has it). On plain Postgres they stay ordinary
  indexed tables and the app logs that. **Verified here against plain
  Postgres only** — no TimescaleDB was available in the development
  sandbox, so the hypertable branch is unexercised; the first Compose run is
  its first test. The live `DeviceRegistry` is still in-memory (simulation
  state, not a catalog).
- `proposed_responses` gained an `alternatives` JSON column. `create_all`
  never alters an existing table, so a database created before this change
  needs `ALTER TABLE proposed_responses ADD COLUMN alternatives JSON;` once
  (new databases get it automatically).
- `database_url` still uses the `+asyncpg` DSN form in `.env.example`;
  `to_sync_url()` rewrites it to `+psycopg` internally — you don't need a
  second URL.

## 3. Docker Compose (backend + frontend + Postgres only)

```bash
cp .env.example .env   # adjust API_PORT/FRONTEND_PORT if either is taken
docker compose up --build
```

What this actually brings up, per `docker-compose.yml`:

| Service | Image/build | Notes |
| --- | --- | --- |
| `db` | `timescale/timescaledb:2.17.2-pg16` | Healthcheck-gated; `backend` waits for it to be healthy before starting |
| `backend` | built from `backend/Dockerfile` (`python:3.12-slim` base) | `REPOSITORY_BACKEND=postgres` is set here directly, so the Postgres-backed repositories above are what a Compose-run backend actually uses, not the in-memory default |
| `frontend` | multi-stage build from `frontend/Dockerfile` (`node:22-alpine` → `nginx:1.27-alpine`) | Serves the real Vite production build via nginx, not the dev server; `VITE_API_BASE_URL` is baked in at build time (Vite has no runtime env step for a static build) |

Resulting URLs: dashboard at `http://localhost:${FRONTEND_PORT:-5173}`,
backend at `http://localhost:${API_PORT:-8000}`. `CORS_ALLOWED_ORIGINS` and
the frontend's build-time `VITE_API_BASE_URL` are wired to stay consistent
automatically if you change either port in `.env`.

**Hyperledger Fabric is deliberately not a Compose service** — see §4
below. `docker compose up` here never starts or touches Fabric at all.

## 4. Hyperledger Fabric (native binaries, not Docker — a locked, disclosed decision)

The architecture spec's original plan was to run Fabric's own
`test-network` sample via Docker Compose. That plan changed in Phase 8, for
the same registry-block reason as §0 above, and the decision was never
reverted: Fabric runs from downloaded native binaries
(`peer`, `orderer`, `cryptogen`, `configtxgen`, `osnadmin`), with chaincode
deployed via Fabric's external-builder mechanism instead of a chaincode
Docker image. This is **this project's own dev-history workaround**, not a
statement that Fabric requires native binaries in general — if your
deployment target has registry access, the original Docker-based
`test-network` approach the architecture spec names is the more standard
path and isn't precluded by anything here; it simply isn't what this
repository's own `blockchain/network/` scripts implement.

```bash
# Prerequisite: a Fabric binary release extracted somewhere, containing
# bin/{peer,orderer,cryptogen,configtxgen,osnadmin} and a config/ directory
export FABRIC_BIN_DIR=/path/to/fabric-dist   # default: /home/claude/fabric-dist

cd blockchain/network/scripts
./generate.sh                     # crypto material + genesis block + core.yaml
./start-network.sh                # orderer + both peers, joined to the channel
./package-chaincode.sh ../../chaincode provenance_1.0 /tmp/provenance.tgz
./deploy-chaincode.sh /tmp/provenance.tgz provenance 1.0 1
./invoke.sh provenance '{"Args":["recordIncident","INC-1","dev-1","ddos","<hash>","2026-10-12T00:00:00Z"]}'
./query.sh provenance '{"Args":["verifyEvidence","<hash>"]}'
```

`./reset.sh` stops the network and wipes all ledger state for a clean
re-run of `generate.sh`. See `blockchain/network/README.md` for the four
non-obvious adaptations this setup needed (TLS SAN handling for the
sandbox's proxy, the etcdraft WAL's hardcoded path, and two others) — read
it before touching `crypto-config.yaml`/`configtx.yaml` or the scripts, it
documents exactly what's easy to silently regress.

To make the backend actually commit to this network instead of using the
mock client, set in `.env`:

```bash
FABRIC_CLIENT_MODE=subprocess
FABRIC_NETWORK_SCRIPTS_DIR=../blockchain/network/scripts
FABRIC_CHAINCODE_NAME=provenance
```

Without these set, `Settings.fabric_client_mode` defaults to `mock` — the
outbox worker and `/blockchain/audit/process` run against
`MockFabricClient`, which doesn't talk to any real network. This is the
default for most dev/test runs; most of this project's own test suite
(and the live-network integration tests specifically) still requires a real
Fabric binary release to be present to exercise the `subprocess` path.

## 5. Full stack, all pieces together

There is no single command that brings up backend + frontend + Postgres +
Fabric at once — Compose intentionally excludes Fabric (§3/§4 above). To
run everything:

1. `docker compose up --build` (or the no-Docker equivalent in §1/§2) for
   backend + frontend + Postgres.
2. Separately, `blockchain/network/scripts/start-network.sh` (§4) for
   Fabric, with `FABRIC_CLIENT_MODE=subprocess` set on the backend.
3. Verify with `POST /blockchain/audit/process` — processed entries should
   show a real `chain_tx_id`, not remain `pending`/`failed`.

This two-part bring-up is itself the disclosed, locked shape of this
deployment, not a missing integration step.
