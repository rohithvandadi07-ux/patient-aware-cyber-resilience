"""Measures the REAL Hyperledger Fabric provenance layer (no mock).

Run against the native-binary network in `blockchain/network/` with the real
chaincode in `blockchain/chaincode/`, through the same `SubprocessFabricClient`
the backend's outbox worker uses. Writes `evaluation/blockchain_evaluation.md`
and `.json`.

What is MEASURED (wall-clock, this machine, this network):

* Commit latency of one write (`record_incident`), end to end through the CLI
  client: proposal, endorsement by both organisations, ordering, and commit
  confirmed by both peers (the client waits for the commit event).
* After a write returns: how long until a query on the Hospital peer sees it.
* Latency of a full five-transaction incident lifecycle
  (incident, decision, approval, response, recovery).
* Read latency (`verify_evidence`).
* Throughput and failure count at several concurrency levels.
* Floor cost of spawning the Fabric CLI once (`peer version`), so the client's
  process-spawn overhead can be separated from Fabric's own work.

What is CHECKED (pass/fail, each with the observed evidence):

* The chaincode's rules hold on a real ledger: write-once incident record,
  rejection of unknown incidents and invalid action categories.
* `verify_evidence` accepts the recorded hash and rejects a hash of the same
  evidence with one field altered.
* Both organisations' peers return the same answer.
* The MAJORITY endorsement policy is enforced: a transaction endorsed by one
  organisation only is invalidated, and leaves no state behind.
* Ledger tamper evidence: every block is fetched, its header-hash chain and data
  hash are recomputed from the raw bytes, and two simulated edits to a COPY of
  the chain are shown to be detected.
* The ledger agrees with the client: every transaction id the client reported as
  committed is found on the ledger with validation code VALID.

What this does NOT show, and the report says so too:

* The network is ONE machine, TWO peers (one per organisation) and ONE Raft
  orderer. A single-node Raft cluster has no orderer fault tolerance, so
  nothing here says anything about availability or Byzantine behaviour.
* Latency includes spawning the Fabric CLI per call (the client shells out),
  and the orderer's batch timeout is 1 s, so about a second of every commit is
  the batch timer. These numbers describe this deployment, not Fabric.
* The tamper check verifies a COPY of the chain with an independent
  implementation of Fabric's hashing. It shows that edits are detectable by
  anyone who re-verifies; it does not claim a peer's files cannot be edited.

Run (from `backend/`):

    python -m app.evaluation.run_blockchain_evaluation            # brings the network up itself
    python -m app.evaluation.run_blockchain_evaluation --use-running   # network already deployed
"""

# ruff: noqa: E501 -- the generated report text is long prose, wrapped by the reader not the linter
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import statistics
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.blockchain.fabric_client import (
    FabricInvocationError,
    SubprocessFabricClient,
    TransientFabricError,
)
from app.blockchain.hashing import hash_payload

REPO_ROOT = Path(__file__).resolve().parents[3]
NETWORK_SCRIPTS_DIR = REPO_ROOT / "blockchain" / "network" / "scripts"
CHAINCODE_DIR = REPO_ROOT / "blockchain" / "chaincode"
FABRIC_BIN_DIR = Path(os.environ.get("FABRIC_BIN_DIR", "/home/claude/fabric-dist"))
CHAINCODE_NAME = "provenance"
DEFAULT_OUT_DIR = REPO_ROOT / "evaluation"
TS = "2026-10-12T00:00:00+00:00"


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested without a network)
# --------------------------------------------------------------------------- #


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile, q in [0, 100]."""
    if not values:
        raise ValueError("percentile of an empty list")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (q / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def summarise_ms(seconds: list[float]) -> dict[str, float]:
    """p50 / p95 / max / mean of `seconds`, expressed in milliseconds."""
    ms = [s * 1000.0 for s in seconds]
    return {
        "n": float(len(ms)),
        "p50_ms": percentile(ms, 50),
        "p95_ms": percentile(ms, 95),
        "max_ms": max(ms),
        "mean_ms": statistics.fmean(ms),
    }


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def parse_message(buf: bytes) -> dict[int, list[Any]]:
    """Minimal protobuf wire-format reader: field number -> list of values
    (int for varints, bytes for length-delimited fields). Enough for Fabric's
    `common.Block`, `BlockHeader` and `BlockData`."""
    fields: dict[int, list[Any]] = {}
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            value = buf[pos : pos + length]
            pos += length
        elif wire == 1:
            value = buf[pos : pos + 8]
            pos += 8
        elif wire == 5:
            value = buf[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        fields.setdefault(number, []).append(value)
    return fields


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_integer(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() // 8) + 1, "big", signed=True)
        # strip redundant leading zero bytes, keeping the sign bit correct
        while len(body) > 1 and body[0] == 0 and not body[1] & 0x80:
            body = body[1:]
    return b"\x02" + _der_length(len(body)) + body


def _der_octets(b: bytes) -> bytes:
    return b"\x04" + _der_length(len(b)) + b


def header_hash(number: int, previous_hash: bytes, data_hash: bytes) -> bytes:
    """Fabric's block header hash: SHA-256 over the ASN.1 DER encoding of
    SEQUENCE { INTEGER number, OCTET STRING previous_hash, OCTET STRING
    data_hash } (protoutil.BlockHeaderHash)."""
    body = _der_integer(number) + _der_octets(previous_hash) + _der_octets(data_hash)
    return hashlib.sha256(b"\x30" + _der_length(len(body)) + body).digest()


def data_hash_of(entries: list[bytes]) -> bytes:
    """Fabric's block data hash: SHA-256 over the concatenated tx envelopes."""
    return hashlib.sha256(b"".join(entries)).digest()


def _tx_id_of(envelope: bytes) -> str:
    """Transaction id from a serialized Fabric `Envelope` (empty for config blocks)."""
    try:
        payload = parse_message(parse_message(envelope)[1][0])
        header = parse_message(payload[1][0])
        channel_header = parse_message(header[1][0])
        return channel_header.get(5, [b""])[0].decode("utf-8", errors="replace")
    except (KeyError, IndexError, ValueError):
        return ""


def validation_code_name(code: int) -> str:
    names = {
        0: "VALID",
        4: "BAD_PAYLOAD",
        9: "DUPLICATE_TXID",
        10: "ENDORSEMENT_POLICY_FAILURE",
        11: "MVCC_READ_CONFLICT",
        12: "PHANTOM_READ_CONFLICT",
    }
    return names.get(code, f"CODE_{code}")


def parse_block(raw: bytes) -> dict[str, Any]:
    """Decode the pieces of a serialized `common.Block` needed to verify it:
    header fields, the transaction envelopes, each transaction's id, and the
    per-transaction validation flags the peer recorded at commit."""
    block = parse_message(raw)
    header = parse_message(block[1][0])
    data = parse_message(block[2][0]) if 2 in block else {}
    entries = list(data.get(1, []))
    flags: bytes = b""
    if 3 in block:
        metadata = parse_message(block[3][0]).get(1, [])
        if len(metadata) > 2:  # index 2 = TRANSACTIONS_FILTER
            flags = metadata[2]
    return {
        "number": header.get(1, [0])[0],
        "previous_hash": header.get(2, [b""])[0],
        "data_hash": header.get(3, [b""])[0],
        "entries": entries,
        "tx_ids": [_tx_id_of(e) for e in entries],
        "tx_flags": list(flags),
    }


def verify_chain(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-verify a list of parsed blocks in order. Returns `ok`, and on failure
    the first offending block number and the reason."""
    for i, block in enumerate(blocks):
        if block["number"] != i:
            return {"ok": False, "block": i, "reason": f"block number {block['number']} at position {i}"}
        if data_hash_of(block["entries"]) != block["data_hash"]:
            return {"ok": False, "block": i, "reason": "data hash does not match the block's transactions"}
        if i > 0:
            prev = blocks[i - 1]
            expected = header_hash(prev["number"], prev["previous_hash"], prev["data_hash"])
            if block["previous_hash"] != expected:
                return {
                    "ok": False,
                    "block": i,
                    "reason": "previous_hash does not match the prior block's header",
                }
    return {"ok": True, "blocks": len(blocks)}


def tamper_payload_byte(blocks: list[dict[str, Any]], block_index: int) -> list[dict[str, Any]]:
    """Copy of `blocks` with one byte of one transaction flipped (header untouched)."""
    copy = [dict(b, entries=list(b["entries"])) for b in blocks]
    target = copy[block_index]
    entry = bytearray(target["entries"][0])
    entry[len(entry) // 2] ^= 0x01
    target["entries"][0] = bytes(entry)
    return copy


def tamper_and_rehash(blocks: list[dict[str, Any]], block_index: int) -> list[dict[str, Any]]:
    """Copy of `blocks` where an attacker flips a byte AND recomputes that
    block's own data hash so the block is self-consistent; only the chain link
    to the next block can then expose it."""
    copy = tamper_payload_byte(blocks, block_index)
    copy[block_index]["data_hash"] = data_hash_of(copy[block_index]["entries"])
    return copy


# --------------------------------------------------------------------------- #
# Network control
# --------------------------------------------------------------------------- #


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=NETWORK_SCRIPTS_DIR, timeout=timeout, capture_output=True, text=True, check=False
    )


def _run_checked(args: list[str], timeout: int) -> None:
    result = _run(args, timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )


def bring_up_network() -> None:
    _run_checked(["./reset.sh"], 60)
    _run_checked(["./generate.sh"], 60)
    _run_checked(["./start-network.sh"], 120)
    with tempfile.TemporaryDirectory() as tmp:
        package = Path(tmp) / "provenance.tgz"
        _run_checked(["./package-chaincode.sh", str(CHAINCODE_DIR), "provenance_1.0", str(package)], 60)
        _run_checked(["./deploy-chaincode.sh", str(package), CHAINCODE_NAME, "1.0", "1"], 240)


def tear_down_network() -> None:
    _run(["./reset.sh"], 60)


def fabric_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = subprocess.run(
            [str(FABRIC_BIN_DIR / "bin" / "peer"), "version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        ).stdout
        for line in text.splitlines():
            if "Version:" in line:
                out["fabric_peer"] = line.split("Version:")[1].strip()
                break
    except Exception:  # pragma: no cover - informational only
        out["fabric_peer"] = "unknown"
    return out


class RecordingClient:
    """Delegates to a real client and remembers the transaction id of every
    write the client reported as committed, so the ledger can be asked afterwards
    whether each of them really is."""

    def __init__(self, inner: SubprocessFabricClient) -> None:
        self._inner = inner
        self.reported_tx_ids: list[str] = []

    def __getattr__(self, name: str):
        attr = getattr(self._inner, name)
        if not name.startswith("record_"):
            return attr

        async def call(*args, **kwargs):
            result = await attr(*args, **kwargs)
            if result.tx_id:
                self.reported_tx_ids.append(result.tx_id)
            return result

        return call


# --------------------------------------------------------------------------- #
# Measurements
# --------------------------------------------------------------------------- #


async def _retrying(call, retries: int = 6, delay: float = 0.4):
    """Run `call()`, retrying only the project's documented transient error.
    Returns (result, retries_used)."""
    used = 0
    while True:
        try:
            return await call(), used
        except TransientFabricError:
            if used >= retries:
                raise
            used += 1
            await asyncio.sleep(delay)


def measure_cli_floor(samples: int = 20) -> dict[str, float]:
    """Time to spawn `peer version` once: the floor cost of one CLI call."""
    times = []
    for _ in range(samples):
        t0 = time.perf_counter()
        subprocess.run([str(FABRIC_BIN_DIR / "bin" / "peer"), "version"], capture_output=True, check=False)
        times.append(time.perf_counter() - t0)
    return summarise_ms(times)


async def measure_writes(client: Any, n: int, run_id: str) -> dict[str, Any]:
    latencies: list[float] = []
    lags: list[float] = []
    retries = 0
    for i in range(n):
        incident_id = f"EVAL-W-{run_id}-{i}"
        evidence = f"evidence-{run_id}-{i}"
        t0 = time.perf_counter()
        _, used = await _retrying(
            lambda incident_id=incident_id, evidence=evidence: client.record_incident(
                incident_id, "dev-eval", "ddos", evidence, TS
            )
        )
        committed = time.perf_counter()
        latencies.append(committed - t0)
        retries += used
        if i < min(n, 20):
            polls = 0
            while True:
                polls += 1
                if await client.verify_evidence(evidence) or polls >= 30:
                    break
                await asyncio.sleep(0.1)
            lags.append(time.perf_counter() - committed)
    return {
        "write_latency": summarise_ms(latencies),
        "commit_to_queryable": summarise_ms(lags) if lags else None,
        "transient_retries": retries,
    }


async def measure_lifecycle(client: Any, n: int, run_id: str) -> dict[str, Any]:
    totals: list[float] = []
    per_step: dict[str, list[float]] = {
        k: [] for k in ("incident", "decision", "approval", "response", "recovery")
    }
    retries = 0
    for i in range(n):
        iid = f"EVAL-L-{run_id}-{i}"
        t_start = time.perf_counter()
        steps = [
            (
                "incident",
                lambda iid=iid, i=i: client.record_incident(iid, "dev-eval", "ddos", f"lc-{run_id}-{i}", TS),
            ),
            (
                "decision",
                lambda iid=iid: client.record_decision(iid, "risk-hash", "RULE-1", "isolate_non_critical"),
            ),
            ("approval", lambda iid=iid: client.record_approval(iid, "nurse-in-charge", "approved", TS)),
            (
                "response",
                lambda iid=iid: client.record_response(iid, "isolate_non_critical", "orchestrator", TS),
            ),
            ("recovery", lambda iid=iid: client.record_recovery(iid, True, None)),
        ]
        for name, call in steps:
            t0 = time.perf_counter()
            _, used = await _retrying(call)
            per_step[name].append(time.perf_counter() - t0)
            retries += used
        totals.append(time.perf_counter() - t_start)
    return {
        "lifecycle_total": summarise_ms(totals),
        "per_step": {k: summarise_ms(v) for k, v in per_step.items()},
        "transient_retries": retries,
    }


async def measure_reads(client: Any, n: int) -> dict[str, float]:
    times = []
    for i in range(n):
        t0 = time.perf_counter()
        await client.verify_evidence(f"never-recorded-{i}")
        times.append(time.perf_counter() - t0)
    return summarise_ms(times)


async def measure_concurrency(
    client: SubprocessFabricClient, levels: list[int], per_level: int, run_id: str
) -> list[dict[str, Any]]:
    results = []
    for level in levels:
        sem = asyncio.Semaphore(level)
        latencies: list[float] = []
        failures: list[str] = []

        async def one(
            i: int,
            level: int = level,
            sem: asyncio.Semaphore = sem,
            latencies: list[float] = latencies,
            failures: list[str] = failures,
        ) -> None:
            async with sem:
                t0 = time.perf_counter()
                try:
                    await client.record_incident(
                        f"EVAL-C-{run_id}-{level}-{i}", "dev-eval", "ddos", f"conc-{run_id}-{level}-{i}", TS
                    )
                    latencies.append(time.perf_counter() - t0)
                except FabricInvocationError as exc:
                    failures.append(str(exc)[:160])

        wall0 = time.perf_counter()
        await asyncio.gather(*(one(i) for i in range(per_level)))
        wall = time.perf_counter() - wall0
        results.append(
            {
                "concurrency": level,
                "submitted": per_level,
                "committed": len(latencies),
                "failed": len(failures),
                "wall_s": wall,
                "committed_tx_per_s": len(latencies) / wall if wall else 0.0,
                "latency": summarise_ms(latencies) if latencies else None,
                "failure_samples": failures[:3],
            }
        )
    return results


# --------------------------------------------------------------------------- #
# Integrity checks
# --------------------------------------------------------------------------- #


def _query_via_org(evidence_hash: str, org: str) -> str:
    args = json.dumps({"Args": ["verifyEvidence", evidence_hash]})
    result = _run(["./query.sh", CHAINCODE_NAME, args, org], 60)
    return result.stdout.strip()


async def integrity_checks(client: Any, run_id: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    # Real evidence object, hashed with the backend's own canonical hashing.
    evidence = {"incident": f"EVAL-I-{run_id}", "attack": "ddos", "flows": 1200, "peak_pps": 48000}
    good_hash = hash_payload(evidence)
    altered_hash = hash_payload({**evidence, "flows": 1201})
    iid = f"EVAL-I-{run_id}"
    await _retrying(lambda: client.record_incident(iid, "dev-eval", "ddos", good_hash, TS))

    # 1. write-once incident record
    try:
        await client.record_incident(iid, "dev-eval", "ddos", "another-hash", TS)
        add(
            "duplicate incident id is rejected (write-once record)",
            False,
            "second recordIncident was accepted",
        )
    except FabricInvocationError as exc:
        add(
            "duplicate incident id is rejected (write-once record)",
            "already has a recordIncident" in str(exc),
            str(exc)[-140:],
        )

    # 2. unknown incident
    try:
        await client.record_decision("EVAL-NEVER-RECORDED", "h", "RULE-1", "isolate_critical")
        add("decision for an unknown incident is rejected", False, "accepted")
    except FabricInvocationError as exc:
        add(
            "decision for an unknown incident is rejected",
            "no recordIncident entry" in str(exc),
            str(exc)[-140:],
        )

    # 3. invalid action category
    try:
        await client.record_decision(iid, "h", "RULE-1", "launch_missiles")
        add("invalid response-action category is rejected", False, "accepted")
    except FabricInvocationError as exc:
        add("invalid response-action category is rejected", "must be one of" in str(exc), str(exc)[-140:])

    # 4. verify_evidence accepts real evidence, rejects altered evidence
    for _ in range(20):
        if await client.verify_evidence(good_hash):
            break
        await asyncio.sleep(0.2)
    ok_true = await client.verify_evidence(good_hash)
    ok_false = not await client.verify_evidence(altered_hash)
    add(
        "verify_evidence accepts the recorded evidence hash",
        ok_true,
        f"sha256 {good_hash[:16]}... found on ledger" if ok_true else "not found",
    )
    add(
        "verify_evidence rejects evidence altered by one field",
        ok_false,
        f"sha256 {altered_hash[:16]}... not on ledger" if ok_false else "altered hash was accepted",
    )

    # 5. both organisations' peers agree
    h = _query_via_org(good_hash, "hospital")
    s = _query_via_org(good_hash, "securityops")
    add(
        "Hospital and SecurityOps peers return the same answer",
        h == s == "true",
        f"hospital={h!r} securityops={s!r}",
    )

    # 5b. two simultaneous writers of the same new incident id: exactly one may win
    race_id = f"EVAL-RACE-{run_id}"
    outcomes = await asyncio.gather(
        client.record_incident(race_id, "dev-eval", "ddos", f"race-A-{run_id}", TS),
        client.record_incident(race_id, "dev-eval", "ddos", f"race-B-{run_id}", TS),
        return_exceptions=True,
    )
    winners = [i for i, o in enumerate(outcomes) if not isinstance(o, BaseException)]
    on_ledger = [await client.verify_evidence(f"race-{'AB'[i]}-{run_id}") for i in (0, 1)]
    add(
        "two simultaneous writers of one incident id: exactly one is reported committed, and only that record is on the ledger",
        len(winners) == 1 and on_ledger == [i == winners[0] for i in (0, 1)],
        f"reported committed: {[('A', 'B')[i] for i in winners]}; on ledger: A={on_ledger[0]}, B={on_ledger[1]}",
    )

    # 6. endorsement policy enforced: one-org endorsement is invalidated, no state left behind
    single_hash = f"single-org-{run_id}"
    args = json.dumps({"Args": ["recordIncident", f"EVAL-ONE-{run_id}", "d", "ddos", single_hash, TS]})
    result = _run(["./invoke-single-org.sh", CHAINCODE_NAME, args, "hospital"], 90)
    combined = result.stdout + result.stderr
    invalidated = result.returncode != 0 and "ENDORSEMENT_POLICY_FAILURE" in combined
    await asyncio.sleep(1.5)
    left_behind = await client.verify_evidence(single_hash)
    add(
        "a transaction endorsed by one organisation only is invalidated (MAJORITY policy)",
        invalidated and not left_behind,
        "status ENDORSEMENT_POLICY_FAILURE, no state written"
        if invalidated and not left_behind
        else f"exit={result.returncode}, state_present={left_behind}",
    )
    return checks


# --------------------------------------------------------------------------- #
# Ledger tamper evidence
# --------------------------------------------------------------------------- #


def ledger_height() -> int:
    out = _run(["./ledger-height.sh"], 30).stdout.strip()
    return int(out)


def fetch_chain() -> list[dict[str, Any]]:
    height = ledger_height()
    blocks = []
    with tempfile.TemporaryDirectory() as tmp:
        for n in range(height):
            path = Path(tmp) / f"b{n}.block"
            _run_checked(["./fetch-block.sh", str(n), str(path)], 60)
            blocks.append(parse_block(path.read_bytes()))
    return blocks


def ledger_accounting(blocks: list[dict[str, Any]], reported_ids: list[str]) -> dict[str, Any]:
    """Cross-check what the client REPORTED as committed against what the ledger
    actually holds: every reported transaction id must be on the ledger and VALID.
    Also tallies every validation outcome on the ledger (invalid transactions are
    kept on the chain, flagged, but never change state)."""
    flag_by_tx: dict[str, int] = {}
    tally: dict[str, int] = {}
    for block in blocks:
        if block["tx_ids"] and len(block["tx_flags"]) != len(block["tx_ids"]):
            raise ValueError(
                f"block {block.get('number')} has {len(block['tx_ids'])} transactions but "
                f"{len(block['tx_flags'])} validation flags: blocks must be fetched from a peer, not the orderer"
            )
        for tx_id, flag in zip(block["tx_ids"], block["tx_flags"], strict=False):
            if tx_id:
                flag_by_tx[tx_id] = flag
                name = validation_code_name(flag)
                tally[name] = tally.get(name, 0) + 1
    reported = set(reported_ids)
    missing = sorted(t for t in reported if t not in flag_by_tx)
    invalid = sorted(t for t in reported if t in flag_by_tx and flag_by_tx[t] != 0)
    return {
        "client_reported_committed": len(reported),
        "reported_and_valid_on_ledger": len(reported) - len(missing) - len(invalid),
        "reported_but_missing_from_ledger": len(missing),
        "reported_but_invalid_on_ledger": len(invalid),
        "ledger_validation_outcomes": tally,
    }


def ledger_tamper_check(
    blocks: list[dict[str, Any]], reported_ids: list[str] | None = None
) -> dict[str, Any]:
    genuine = verify_chain(blocks)
    candidates = [i for i, b in enumerate(blocks) if b["entries"] and 0 < i < len(blocks) - 2]
    target = candidates[len(candidates) // 2] if candidates else None
    out: dict[str, Any] = {
        "blocks": len(blocks),
        "transactions": sum(len(b["entries"]) for b in blocks),
        "genuine_chain": genuine,
        "tamper_target_block": target,
        "accounting": ledger_accounting(blocks, reported_ids or []),
    }
    if target is not None:
        out["edit_one_byte_of_a_transaction"] = verify_chain(tamper_payload_byte(blocks, target))
        out["edit_and_recompute_that_blocks_data_hash"] = verify_chain(tamper_and_rehash(blocks, target))
    return out


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def _row(label: str, s: dict[str, float]) -> str:
    return f"| {label} | {s['n']:.0f} | {s['p50_ms']:.0f} | {s['p95_ms']:.0f} | {s['max_ms']:.0f} |"


def render_markdown(r: dict[str, Any]) -> str:
    w = r["writes"]
    lc = r["lifecycle"]
    lines = [
        "# Blockchain layer: measurements on a real Hyperledger Fabric network",
        "",
        f"Generated {r['generated_at']}. Real Fabric {r['environment'].get('fabric_peer', '?')} binaries, two organisations (Hospital, "
        "SecurityOps) with one peer each, one Raft orderer, the real provenance chaincode, driven through the backend's own "
        "`SubprocessFabricClient`. No mocks. Method and limits are in `backend/app/evaluation/run_blockchain_evaluation.py`.",
        "",
        "## Scope of the claim",
        "",
        f"- Machine: {r['environment']['cpus']} CPUs, one host. Peers, orderer and chaincode all share it.",
        "- **One Raft consenter**: this network has no orderer fault tolerance. Nothing below speaks to availability or to "
        "Byzantine or malicious-orderer behaviour.",
        "- Every call spawns the Fabric CLI, and the orderer batch timeout is 1 s, so these are latencies of THIS deployment, not "
        f"of Fabric. One CLI spawn alone costs about {r['cli_floor']['p50_ms']:.0f} ms here.",
        "- One run on one machine; no repeated trials, so no confidence intervals.",
        "",
        "## Integrity checks (pass/fail)",
        "",
        "| Check | Result | Observed |",
        "|---|---|---|",
    ]
    for c in r["integrity"]:
        lines.append(
            f"| {c['check']} | {'PASS' if c['passed'] else 'FAIL'} | {c['detail'].replace('|', '/')} |"
        )
    t = r["ledger_tamper"]
    gen = t["genuine_chain"]
    lines += [
        "",
        "## Ledger tamper evidence",
        "",
        f"All {t['blocks']} blocks ({t['transactions']} transactions) were fetched from the Hospital peer and re-verified with an independent "
        "implementation of Fabric's block hashing (header hash chain plus data hash, recomputed from the raw block bytes).",
        "",
        f"- Genuine chain: {'verified, every link intact' if gen['ok'] else 'FAILED at block ' + str(gen.get('block')) + ': ' + gen.get('reason', '')}.",
    ]
    if t.get("tamper_target_block") is not None:
        a = t["edit_one_byte_of_a_transaction"]
        b = t["edit_and_recompute_that_blocks_data_hash"]
        lines += [
            f"- Edit one byte of one transaction in block {t['tamper_target_block']} (on a copy): "
            f"{'DETECTED at block ' + str(a['block']) + ' (' + a['reason'] + ')' if not a['ok'] else 'NOT detected'}.",
            "- Same edit, with the attacker also recomputing that block's own data hash so the block looks self-consistent: "
            f"{'DETECTED at block ' + str(b['block']) + ' (' + b['reason'] + ')' if not b['ok'] else 'NOT detected'}.",
        ]
    acc = t["accounting"]
    lines += [
        "",
        "### Does the ledger agree with what the client reported?",
        "",
        f"Every transaction id the backend's client reported as committed during this run was looked up in the fetched blocks: "
        f"{acc['client_reported_committed']} reported, {acc['reported_and_valid_on_ledger']} VALID on the ledger, "
        f"{acc['reported_but_missing_from_ledger']} missing, {acc['reported_but_invalid_on_ledger']} invalid.",
        f"Validation outcomes recorded on the ledger overall: {', '.join(f'{k} {v}' for k, v in sorted(acc['ledger_validation_outcomes'].items()))}. "
        "Invalid transactions stay on the chain, flagged, and never change state; the ones here were produced on purpose by the "
        "one-organisation-endorsement and simultaneous-writer checks.",
    ]
    lines += [
        "",
        "This shows edits are detectable by anyone who re-verifies the chain. It does not claim a peer's files cannot be edited, "
        "and it checks a copy of the chain, not the live peers.",
        "",
        "## Latency (sequential, milliseconds)",
        "",
        "| Operation | n | p50 | p95 | max |",
        "|---|---|---|---|---|",
        _row("Fabric CLI spawn alone (`peer version`), the floor", r["cli_floor"]),
        _row("Write: `record_incident`, until both peers have committed it", w["write_latency"]),
    ]
    if w.get("commit_to_queryable"):
        lines.append(
            _row(
                "After a write returns: time until a query sees it (polled every 100 ms)",
                w["commit_to_queryable"],
            )
        )
    lines.append(_row("Read: `verify_evidence`", r["reads"]))
    lines.append(_row("Full 5-transaction incident lifecycle", lc["lifecycle_total"]))
    for name, s in lc["per_step"].items():
        lines.append(_row(f"  lifecycle step: {name}", s))
    lines += [
        "",
        f"Transient endorsement-race retries needed (the documented timing artifact): writes {w['transient_retries']}, "
        f"lifecycle {lc['transient_retries']}.",
        "",
        "## Concurrency",
        "",
        "| Concurrent clients | Submitted | Committed | Failed | Wall (s) | Committed tx/s | p50 (ms) | p95 (ms) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c in r["concurrency"]:
        lat = c["latency"] or {"p50_ms": float("nan"), "p95_ms": float("nan")}
        lines.append(
            f"| {c['concurrency']} | {c['submitted']} | {c['committed']} | {c['failed']} | {c['wall_s']:.1f} | "
            f"{c['committed_tx_per_s']:.2f} | {lat['p50_ms']:.0f} | {lat['p95_ms']:.0f} |"
        )
    failures = [c for c in r["concurrency"] if c["failed"]]
    if failures:
        lines += ["", "Failure samples:"]
        for c in failures:
            for s in c["failure_samples"]:
                lines.append(f"- concurrency {c['concurrency']}: `{s}`")
    lines += [
        "",
        "## A defect this evaluation found, now fixed",
        "",
        "The first run of this evaluation exposed that `invoke.sh` called `peer chaincode invoke` without `--waitForEvent`. The "
        "client therefore returned success once a transaction was endorsed and handed to the orderer, not once it was committed: "
        "an immediate duplicate `recordIncident` was reported as accepted (the ledger itself kept the first record), the next call "
        "could be endorsed against a peer that had not yet applied the previous block (the 'transient endorsement race' the outbox "
        "worker was already retrying), and, worse, a transaction invalidated at commit would still have been reported as "
        "committed, so the outbox could mark a provenance record CONFIRMED that never reached the ledger. `invoke.sh` now waits "
        "for both peers' commit events and exits non-zero for an invalidated transaction. The latencies in this report are "
        "measured with the fix; the checks above, including the simultaneous-writer check, and the integration tests in "
        "`backend/tests/test_blockchain_integration.py` guard against a regression.",
        "",
        "## Reading this honestly",
        "",
        "- A write takes about one second mostly because the orderer's batch timeout is 1 s and the client waits for both peers to commit; the write rate is also bounded by CLI process spawning on a small shared machine. A Fabric SDK "
        "client with persistent connections, and a tuned batch timeout, would change these numbers; they are not a Fabric benchmark.",
        "- The system writes only a handful of provenance transactions per incident, and incidents are rare compared with flows, so "
        "per-incident latency is the relevant figure, not peak throughput.",
        "- Provenance is written through the outbox, off the detection and response path, so these latencies do not delay containment.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


async def run(args: argparse.Namespace) -> dict[str, Any]:
    run_id = datetime.now(UTC).strftime("%H%M%S")
    client = RecordingClient(
        SubprocessFabricClient(network_scripts_dir=NETWORK_SCRIPTS_DIR, chaincode_name=CHAINCODE_NAME)
    )
    result: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {**fabric_versions(), "cpus": os.cpu_count()},
        "run_id": run_id,
    }
    print("measuring CLI floor", flush=True)
    result["cli_floor"] = measure_cli_floor()
    print("integrity checks", flush=True)
    result["integrity"] = await integrity_checks(client, run_id)
    print("write latency", flush=True)
    result["writes"] = await measure_writes(client, args.writes, run_id)
    print("read latency", flush=True)
    result["reads"] = await measure_reads(client, args.reads)
    print("lifecycle", flush=True)
    result["lifecycle"] = await measure_lifecycle(client, args.lifecycles, run_id)
    print("concurrency", flush=True)
    result["concurrency"] = await measure_concurrency(client, args.levels, args.per_level, run_id)
    print("fetching and re-verifying the whole chain", flush=True)
    result["ledger_tamper"] = ledger_tamper_check(fetch_chain(), client.reported_tx_ids)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--use-running", action="store_true", help="use an already-deployed network; do not reset it"
    )
    parser.add_argument("--keep-network", action="store_true", help="leave the network running afterwards")
    parser.add_argument("--writes", type=int, default=40)
    parser.add_argument("--reads", type=int, default=40)
    parser.add_argument("--lifecycles", type=int, default=10)
    parser.add_argument("--levels", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--per-level", type=int, default=24)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    if not (FABRIC_BIN_DIR / "bin" / "peer").exists():
        raise SystemExit(f"no Fabric binaries at {FABRIC_BIN_DIR}; see blockchain/network/README.md")

    if not args.use_running:
        print("bringing the network up", flush=True)
        bring_up_network()
    try:
        result = asyncio.run(run(args))
    finally:
        if not args.use_running and not args.keep_network:
            tear_down_network()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "blockchain_evaluation.json").write_text(json.dumps(result, indent=2, default=str))
    (args.out_dir / "blockchain_evaluation.md").write_text(render_markdown(result))
    print(f"wrote reports to {args.out_dir}", flush=True)


if __name__ == "__main__":
    main()
