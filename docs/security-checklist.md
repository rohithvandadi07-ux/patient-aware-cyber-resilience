# Phase 12 security checklist

Architecture spec Section 19's literal Phase 12 gate is: **"Security checklist
from the brief's Section 16 is verified item by item."**

**Disclosure, up front, because getting this wrong would be worse than not
having a checklist at all:** the original brief document's own Section 16 —
the actual checklist the gate refers to — is not recoverable in this
session. It was never committed to this repository (only `docs/architecture.md`,
this project's own Phase 0 *response* to the brief, was committed — the
brief itself is a separate, external document), it is not in the Claude
Project's docs or memory, and it does not appear among Darshan's saved
artifacts. Darshan was asked where it lives and could not locate it either.

Rather than invent a checklist and label it "the brief's Section 16" —
which would misrepresent its source exactly where honesty about sourcing
matters most — the checklist below is explicitly **my own**, built from
standard, named frameworks (OWASP API Security Top 10 2023, OWASP ASVS
Level 1, CWE Top 25) and scoped to this specific system's actual attack
surface: a FastAPI backend with Pydantic schemas everywhere, a React/Vite
frontend, a Hyperledger Fabric blockchain integration reached by shelling
out to real scripts, and no production datastore or authentication layer
yet (both are pre-existing, disclosed, deliberately-deferred decisions from
earlier phases, not something this checklist invents or silently fixes).
Every item below was actually checked against the real code or actually run
as a real scan — nothing here is asserted without the command or file read
that backs it.

If the real brief's Section 16 surfaces later, this document should be
re-run against it and this disclosure updated or removed.

## 1. Dependency vulnerabilities

| Item | Status | Detail |
| --- | --- | --- |
| Backend Python dependencies scanned for known CVEs | **Fixed** | `pip-audit` found 16 known vulnerabilities across `starlette` (6 distinct CVEs: HTTP Range-header quadratic-time DoS, Host-header-based `request.url` reconstruction, unenforced `urlencoded` form field/size limits, a Windows `StaticFiles` SSRF via UNC paths, an `HTTPEndpoint` HTTP-verb dispatch issue, a non-`/`-prefixed-path `request.url` issue — pulled in transitively via `fastapi==0.115.6`) and `pytest` (a predictable `/tmp/pytest-of-{user}` directory name, local DoS/privilege risk). Fixed by bumping `fastapi` to `0.143.0` (resolves `starlette` to `1.7.0`, past every flagged CVE) and `pytest`/`pytest-asyncio` to `9.0.3`/`1.4.0` (compatible pins). Re-ran `pip-audit` after: **0 known vulnerabilities**. Full backend suite (342 tests), the Phase 11 E2E suite (2 tests), and `ruff check` all still pass against the upgraded stack — see `backend/requirements.txt`/`requirements-dev.txt` for the recorded rationale. |
| Frontend npm dependencies scanned for known CVEs | **Pass** | `npm audit` in `frontend/`: 0 vulnerabilities. |
| Chaincode npm dependencies scanned for known CVEs | **Pass** | `npm audit` in `blockchain/chaincode/`: 0 vulnerabilities. |

## 2. Secrets management

| Item | Status | Detail |
| --- | --- | --- |
| No committed private keys / certs / tokens | **Pass** | `detect-secrets scan` over every git-tracked file (249 files, explicit file list — not a blind recursive scan, which would have also walked `.venv`/`node_modules`) found two hits, both reviewed as false positives (see below). A separate grep for PEM private-key headers (`BEGIN ... PRIVATE KEY`) across tracked files found none. No `.pem`/`.key`/`.p12` files are tracked at all. `blockchain/network/crypto-config/` (where Fabric's generated certs/keys actually live) is git-ignored, never committed; the `.gitignore` carve-out for `.crt` files under `blockchain/network/**` is currently moot since nothing under that path is tracked. |
| `.env.example` contains only placeholders | **Pass (reviewed)** | `detect-secrets` flagged `DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/...` in both `.env.example` and `backend/app/core/config.py`'s matching default as "Basic Auth Credentials." This is the same dev-only `postgres`/`postgres` default `docker-compose.yml` itself sets for its Postgres container — not a leaked real credential, and `config.py`'s own module docstring already states every default here is "safe for local development only" and expected to be overridden via `.env`/environment variables in any real deployment. Reviewed and accepted as-is, not changed. |
| No hardcoded credentials in Fabric network scripts | **Pass** | Grepped `blockchain/network/scripts/*.sh` for `password`/`secret`/`apikey`: no matches. Identity material (MSP paths, TLS cert paths) is read from the generated, git-ignored `crypto-config`/`organizations` directories, never inlined. |

## 3. Injection and subprocess safety

| Item | Status | Detail |
| --- | --- | --- |
| No shell-injection surface in the one real subprocess call site | **Pass (verified)** | `SubprocessFabricClient._run_script` (`backend/app/blockchain/fabric_client.py`) uses `asyncio.create_subprocess_exec` — arguments are passed as a real argv list, never interpolated into a shell string (`shell=True` is not used anywhere in this codebase; confirmed by grep). `invoke.sh`/`query.sh` themselves also correctly double-quote every variable expansion (`"$ARGS_JSON"`, etc.), and the JSON payload itself is built with `json.dumps` (`_args_json`), which escapes embedded quotes correctly — so even an incident/device ID containing shell metacharacters or quote characters cannot break out of the argument boundary. |
| No `eval`/`exec`/`os.system` anywhere in the backend | **Pass** | Grepped `app/` (excluding tests) for `os.system`, `shell=True`, `eval(`, `exec(`: no matches outside the one reviewed subprocess call above. |
| Model-artifact deserialization (`joblib.load`, pickle-based) only ever loads a fixed, server-side path | **Pass (verified)** | `_DEFAULT_MODEL_PATH` (`backend/app/api/detections.py`) is a hardcoded constant (`experiments/models/random_forest.joblib`); no endpoint accepts a user-supplied model path. `joblib.load`/pickle deserialization is unsafe in general for untrusted input, but nothing here ever feeds it untrusted input — documented here as a standing constraint for any future change, not a current vulnerability. |
| No raw SQL (and therefore no SQL injection surface) | **Pass** | Every repository behind the API is still in-memory (Postgres migration is a disclosed, not-yet-built Phase 9+ gap, unchanged by this phase) — there is no query-building code to audit yet. Revisit this item when the Postgres migration actually happens. |
| No XSS surface in the frontend | **Pass** | Grepped `frontend/src/` for `dangerouslySetInnerHTML` and direct `innerHTML` assignment: no matches. All incident/agent/evidence data renders through ordinary JSX text interpolation, which React escapes by default. |

## 4. Error handling and information disclosure

| Item | Status | Detail |
| --- | --- | --- |
| Debug mode does not leak stack traces by default | **Fixed** | `Settings.debug` (`backend/app/core/config.py`) defaulted to `True`, passed straight through to FastAPI's `debug` flag, which controls Starlette's `ServerErrorMiddleware` — when true, an *unhandled* exception returns a full traceback (file paths, source lines, local variable values) in the HTTP response body instead of a generic 500. Changed the default to `False` (fail safe); local development opts in explicitly via `DEBUG=true` in `.env` (`.env.example` already documents this), rather than inheriting the permissive behavior silently. No test depended on the old default (checked via grep for `.debug` usage across `app/`/`tests/`) and the full suite still passes. |
| Blockchain provenance schemas carry only hashes/metadata, never raw evidence or patient data | **Pass (re-verified)** | Re-read `backend/app/schemas/blockchain.py` in full: `IncidentProvenance`, `DecisionProvenance`, `ApprovalProvenance`, `ResponseProvenance`, `RecoveryProvenance` carry only IDs, enum categories, hashes, an approver's identity label, and timestamps — no telemetry, no log content, no patient-identifying fields. `evidence_ref` is hashed (`hash_payload`) before it ever reaches a provenance object (`app/api/incidents.py`). This re-confirms, against the current code rather than by assumption, the design claim stated in every earlier phase's docs. |
| Structured logging doesn't log secrets or raw sensitive payloads | **Pass (verified)** | Grepped every `logger.*` call site across `app/` (excluding tests): only two modules log anything — `cybersecurity/detection_service.py` (model confidence/label diagnostics) and `blockchain/outbox_worker.py` (outbox entry id, record type, chain_tx_id, and the Fabric client's own exception text on failure). No module anywhere else calls a logger at all, so there's no log site in the response/recovery/approval path to leak anything from. The outbox worker's logged exception text can only ever echo the already-hashed/metadata-only provenance fields (Section 3 above confirms nothing raw ever reaches a blockchain schema in the first place), so even a full chaincode-invocation error message logged verbatim can't surface patient data or secrets. |

## 5. Network and transport

| Item | Status | Detail |
| --- | --- | --- |
| CORS allowlist is explicit, never a wildcard | **Pass (no regression since Phase 10)** | Re-checked `app_factory.py`'s `_register_middleware`: `allow_origins=settings.cors_allowed_origins` (an explicit list, default `["http://localhost:5173", "http://127.0.0.1:5173"]`), `allow_credentials=False`. Unchanged since Phase 10. |
| Hyperledger Fabric peer/orderer communication is TLS-enabled, not silently weakened by the Phase 8 sandbox workarounds | **Pass (re-verified)** | Re-read `invoke.sh`, `query.sh`, and the external builder's `run` script in full: all three set `CORE_PEER_TLS_ENABLED=true` with real CA/root cert paths — mutual TLS, not one-way. `peercfg/core.yaml`'s `skipBlockVerification: false` is Fabric's own stock default, untouched. The Phase 8 TLS-SAN fix (adding `127.0.0.1`/`localhost` to `cryptogen`'s SANs) *added* a valid SAN rather than disabling hostname verification — confirmed by re-reading `crypto-config.yaml`'s intent as documented in the Claude Project's architecture-decisions doc. The `run` script's mTLS client-key material is written under a `mktemp -d` scratch directory (mode `0700` by default — inaccessible to other local users regardless of the individual files' own mode bits inside it). |
| Rate limiting / request-size limits on the API | **Known gap, disclosed, not fixed this phase** | No rate-limiting or request-body-size-limiting middleware exists anywhere in the backend (confirmed by grep: no `slowapi`, no custom limiter, no `max_content_length`-style configuration). This is a real gap, but adding a rate limiter is a new dependency and a new piece of always-on middleware with its own behavior to test — the same category of decision this project has consistently treated as a deliberate scope choice rather than something to bolt on unasked (see authentication, Postgres migration, background outbox draining — all named, deferred, not silently worked around). Appropriate to add alongside the authentication layer Section 15 already designs for but has not implemented through at least Phase 9. |

## 6. Authentication and authorization (carried-forward, not this phase's gate)

| Item | Status | Detail |
| --- | --- | --- |
| Authentication/authorization | **Known gap, unchanged** | Still designed-for, not implemented — the same disclosed decision named in every phase since Phase 9 (Section 15's own framing). Phase 12's literal gate is a security checklist verification pass, not "add auth"; adding a full auth layer here, un-asked, would be exactly the kind of scope invention this project has avoided at every other phase boundary. Flagged here so it isn't lost track of, not quietly re-deferred without a note. |

## What this phase did NOT do, and why

- **Did not add rate limiting or an authentication layer.** Both are real, legitimate hardening items, but both are new features with their own design surface (what identity model? what rate-limit scope — per-IP, per-incident?) — adding either un-asked would be scope invention of exactly the kind this project has avoided at every other phase boundary. Documented above as disclosed, known gaps instead.
- **Did not migrate to Postgres** or otherwise change the storage layer — unrelated to this phase's gate, and a disclosed Phase 9+ gap already.
- **Did not re-run the full Fabric `test-network` end-to-end** (Phase 8's live-network integration test) as part of this pass — this checklist's network-security items were verified by reading the real, committed scripts/configs that *define* the network's security posture, which is what changes (or doesn't) between phases; the live-network test itself is unchanged since Phase 8 and still gated on real Fabric binaries being present, exactly as before.

## Verification

Full backend suite: 342 tests passing (unchanged count; all pass against the
upgraded `fastapi`/`starlette`/`pytest`/`pytest-asyncio`), `ruff check`
clean. Full frontend suite: 46 tests passing, `oxlint`/`npm run build`
clean. Phase 11's E2E suite: 2/2 passing against the upgraded backend
stack, through a real browser. `pip-audit`: 0 known vulnerabilities (was
16). `npm audit` (frontend and chaincode): 0 known vulnerabilities, both
before and after this pass.
