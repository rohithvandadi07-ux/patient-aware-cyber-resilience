# frontend

L10 of the architecture. The Healthcare SOC dashboard — React + TypeScript. Built
around the incident lifecycle as one shared incident-detail view with distinct,
equally-weighted cyber-risk and clinical-risk panels, not cyber risk as the main
event with clinical context as a footnote (architecture spec Section 16).

Status: **Phase 10 complete.** Toolchain: Vite 8 + React 19 + TypeScript 6,
Tailwind CSS v4 (the component-library choice Section 5 deferred to this phase
— utility classes over a component kit, since the dashboard's layout needs are
bespoke, not admin-template boilerplate), React Router v7, TanStack React
Query v5 (one shared cache so, e.g., executing a response invalidates exactly
the queries that change — the proposed decision, the executed-response list,
the audit trail), Vitest + React Testing Library for component tests. `npm
run build`, `npm run test` (46 tests), and `npm run lint` all genuinely pass
as of this commit — not asserted, run.

Phase 10's gate (Section 19: "one incident's full lifecycle is viewable and
the dual-risk panel is visually distinct, per Section 16") is exercised
directly by `src/routes/IncidentDetail.fullLifecycle.test.tsx`, which renders
every panel together for one incident shaped exactly like what
`backend/tests/test_lifecycle_integration.py` proved the real API produces
end to end for a fully resolved incident.

## Scripts

- `npm run dev` — Vite dev server (default `http://localhost:5173`; the backend's
  `Settings.cors_allowed_origins` allows this origin by default — see
  `backend/app/core/app_factory.py`).
- `npm run build` — type-check (`tsc -b`) then production build.
- `npm run test` — Vitest, single run (CI-friendly). `npm run test:watch` for
  interactive development.
- `npm run lint` — `oxlint` (the scaffolder's default; faster than ESLint, same
  category of checks).

## Docker (Phase 14)

`Dockerfile` is a two-stage build: `npm run build`'s real output served by
nginx (`nginx.conf` adds the one thing a static file server needs over a
dev server — SPA fallback for React Router's client-side routes). Normally
built via the root `docker-compose.yml`, not standalone, since
`VITE_API_BASE_URL` is a build arg that file sets to match the backend's
published port. Not build-verified in this project's development sandbox
— see the root `README.md`'s "Docker" section for why (every container
registry this sandbox tried is blocked) and what's actually been checked
instead (`docker compose config`'s syntax validation).

## Layout

- `src/api/types.ts` — hand-maintained TypeScript mirror of every backend
  Pydantic schema and enum, field for field, including nullability (no
  OpenAPI-codegen step yet — the API surface is still small enough to keep in
  sync by eye; worth revisiting if it grows).
- `src/api/client.ts` — one typed function per endpoint across all 12 Phase 9
  resource routers.
- `src/api/queries.ts` — React Query hooks (`queryKeys` + query/mutation
  hooks) over `client.ts`.
- `src/api/riskAssessmentFromTraces.ts`, `proposeResponseFromTraces.ts`,
  `recoveryResultFromTraces.ts` — build real request bodies for the three
  backend endpoints that are deliberately stateless/unpersisted
  (`/risk-assessments`, `/responses/proposed`'s inputs, `/recovery`) out of
  an incident's actual agent-trace records, never out of synthetic data. See
  each file's own doc comment for why this is safe (`app/agents/base.py`
  records each trace's `output_payload` as the real agent's own full model
  dump).
- `src/agentLabels.ts` — the five real agents, in pipeline order, with their
  human-readable labels. Shared by the Agent Activity panel and the
  "what's missing" messages above so they never spell an agent two ways.
- `src/components/` — the incident-detail sub-panels: `DualRiskPanel` (the
  Section 16 gate component), `AgentActivityPanel`, `EvidencePanel`,
  `ResponsePanel`, `RecoveryPanel`, `BlockchainAuditPanel`, plus the shared
  `Panel`/`StatusBadge`/`Layout` building blocks. Every panel renders real
  data from its query hook or an explicit "not yet"/"not run" state — never
  placeholder content.
- `src/routes/` — `IncidentList` and `IncidentDetail`, the two route-level
  views, both under the shared `Layout` shell.
- `src/test/setup.ts` — Vitest/RTL global setup (`@testing-library/jest-dom`
  matchers).

## What's NOT here yet

No authentication (Section 15: designed-for, not implemented, through at
least Phase 9). No live polling/websocket updates — the backend itself has
no always-on push mechanism yet (`/blockchain/audit`'s outbox drain is a
manual `POST`, not a background loop; see `backend/app/blockchain/README.md`),
so the dashboard reads on load/action rather than subscribing to anything.
No automatic multi-agent orchestration — the same open decision named in
`backend/app/agents/README.md` and `backend/app/agents/llm_client.py` (no
live LLM backend is wired in anywhere in this project yet). The dual-risk,
response-proposal, and recovery-submission actions on the incident-detail
page only enable once the real agent traces they depend on already exist
(from a real backend run, or `test_lifecycle_integration.py`'s scripted one)
— this dashboard does not, and will not, invent agent output to make a
panel look populated.
