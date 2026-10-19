"""Network-free tests for the pure parts of run_blockchain_evaluation.py:
percentiles, the protobuf reader, Fabric's block hashing, and chain
verification / tamper detection on a synthetic chain."""

from __future__ import annotations

import hashlib

import pytest

from app.evaluation import run_blockchain_evaluation as bc


def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field_bytes(number: int, value: bytes) -> bytes:
    return _encode_varint((number << 3) | 2) + _encode_varint(len(value)) + value


def _field_varint(number: int, value: int) -> bytes:
    return _encode_varint(number << 3) + _encode_varint(value)


def _make_chain(n: int) -> list[dict]:
    blocks: list[dict] = []
    prev_header = b""
    for i in range(n):
        entries = [f"tx-{i}-a".encode(), f"tx-{i}-b".encode()]
        data_hash = bc.data_hash_of(entries)
        block = {"number": i, "previous_hash": prev_header, "data_hash": data_hash, "entries": entries}
        prev_header = bc.header_hash(i, block["previous_hash"], data_hash)
        blocks.append(block)
    return blocks


def test_percentile_interpolates_and_validates():
    assert bc.percentile([1, 2, 3, 4], 50) == 2.5
    assert bc.percentile([7], 95) == 7
    assert bc.percentile([1, 2, 3, 4, 5], 0) == 1
    assert bc.percentile([1, 2, 3, 4, 5], 100) == 5
    with pytest.raises(ValueError):
        bc.percentile([], 50)


def test_summarise_ms_converts_seconds():
    s = bc.summarise_ms([0.1, 0.2, 0.3])
    assert s["n"] == 3
    assert s["p50_ms"] == pytest.approx(200.0)
    assert s["max_ms"] == pytest.approx(300.0)


def test_parse_message_reads_varints_and_bytes():
    raw = _field_varint(1, 300) + _field_bytes(2, b"abc") + _field_bytes(2, b"def")
    parsed = bc.parse_message(raw)
    assert parsed[1] == [300]
    assert parsed[2] == [b"abc", b"def"]


def test_parse_block_round_trip():
    header = _field_varint(1, 7) + _field_bytes(2, b"\x01" * 32) + _field_bytes(3, b"\x02" * 32)
    data = _field_bytes(1, b"envelope-1") + _field_bytes(1, b"envelope-2")
    raw = _field_bytes(1, header) + _field_bytes(2, data)
    block = bc.parse_block(raw)
    assert block["number"] == 7
    assert block["previous_hash"] == b"\x01" * 32
    assert block["data_hash"] == b"\x02" * 32
    assert block["entries"] == [b"envelope-1", b"envelope-2"]


def test_header_hash_is_sha256_of_der_sequence():
    # number 0, empty previous hash, 2-byte data hash: SEQUENCE{02 01 00, 04 00, 04 02 aa bb}
    der = b"\x30\x09" + b"\x02\x01\x00" + b"\x04\x00" + b"\x04\x02\xaa\xbb"
    assert bc.header_hash(0, b"", b"\xaa\xbb") == hashlib.sha256(der).digest()


def test_der_integer_keeps_sign_bit_correct():
    assert bc._der_integer(127) == b"\x02\x01\x7f"
    assert bc._der_integer(128) == b"\x02\x02\x00\x80"
    assert bc._der_integer(256) == b"\x02\x02\x01\x00"


def test_genuine_chain_verifies():
    assert bc.verify_chain(_make_chain(6)) == {"ok": True, "blocks": 6}


def test_flipping_a_transaction_byte_is_detected_at_that_block():
    chain = _make_chain(6)
    result = bc.verify_chain(bc.tamper_payload_byte(chain, 3))
    assert result["ok"] is False
    assert result["block"] == 3
    assert "data hash" in result["reason"]


def test_rehashing_the_tampered_block_is_still_caught_by_the_next_link():
    chain = _make_chain(6)
    result = bc.verify_chain(bc.tamper_and_rehash(chain, 3))
    assert result["ok"] is False
    assert result["block"] == 4
    assert "previous_hash" in result["reason"]


def test_tamper_helpers_do_not_mutate_the_original_chain():
    chain = _make_chain(4)
    bc.tamper_and_rehash(chain, 2)
    assert bc.verify_chain(chain)["ok"] is True


def test_out_of_order_blocks_fail():
    chain = _make_chain(4)
    chain[1], chain[2] = chain[2], chain[1]
    assert bc.verify_chain(chain)["ok"] is False


def _envelope(tx_id: str) -> bytes:
    channel_header = _field_varint(1, 3) + _field_bytes(5, tx_id.encode())
    header = _field_bytes(1, channel_header)
    payload = _field_bytes(1, header) + _field_bytes(2, b"data")
    return _field_bytes(1, payload)


def test_parse_block_extracts_tx_ids_and_validation_flags():
    header = _field_varint(1, 4) + _field_bytes(2, b"\x01" * 32) + _field_bytes(3, b"\x02" * 32)
    data = _field_bytes(1, _envelope("tx-aaa")) + _field_bytes(1, _envelope("tx-bbb"))
    metadata = (
        _field_bytes(1, b"sig")
        + _field_bytes(1, b"lastconfig")
        + _field_bytes(1, bytes([0, 11]))  # index 2: VALID, MVCC_READ_CONFLICT
    )
    raw = _field_bytes(1, header) + _field_bytes(2, data) + _field_bytes(3, metadata)
    block = bc.parse_block(raw)
    assert block["tx_ids"] == ["tx-aaa", "tx-bbb"]
    assert block["tx_flags"] == [0, 11]


def test_validation_code_names():
    assert bc.validation_code_name(0) == "VALID"
    assert bc.validation_code_name(11) == "MVCC_READ_CONFLICT"
    assert bc.validation_code_name(10) == "ENDORSEMENT_POLICY_FAILURE"
    assert bc.validation_code_name(99) == "CODE_99"


def test_ledger_accounting_flags_reported_but_invalid_and_missing_transactions():
    blocks = [
        {"tx_ids": ["good-1", "good-2"], "tx_flags": [0, 0]},
        {"tx_ids": ["bad-1"], "tx_flags": [11]},
    ]
    acc = bc.ledger_accounting(blocks, ["good-1", "good-2", "bad-1", "never-ordered"])
    assert acc["client_reported_committed"] == 4
    assert acc["reported_and_valid_on_ledger"] == 2
    assert acc["reported_but_invalid_on_ledger"] == 1
    assert acc["reported_but_missing_from_ledger"] == 1
    assert acc["ledger_validation_outcomes"] == {"VALID": 2, "MVCC_READ_CONFLICT": 1}


def test_ledger_accounting_refuses_blocks_without_validation_flags():
    # e.g. blocks fetched from the orderer: the flags are added by the peer at commit.
    blocks = [{"number": 3, "tx_ids": ["a"], "tx_flags": []}]
    with pytest.raises(ValueError, match="fetched from a peer"):
        bc.ledger_accounting(blocks, ["a"])


def test_ledger_accounting_is_clean_when_everything_reported_is_valid():
    blocks = [{"tx_ids": ["a", "b"], "tx_flags": [0, 0]}]
    acc = bc.ledger_accounting(blocks, ["a", "b"])
    assert acc["reported_and_valid_on_ledger"] == 2
    assert acc["reported_but_invalid_on_ledger"] == 0
    assert acc["reported_but_missing_from_ledger"] == 0


def test_render_markdown_includes_all_sections():
    summary = {"n": 3.0, "p50_ms": 1.0, "p95_ms": 2.0, "max_ms": 3.0, "mean_ms": 1.5}
    report = {
        "generated_at": "2026-10-16T00:00:00+00:00",
        "environment": {"fabric_peer": "v2.5.9", "cpus": 2},
        "cli_floor": summary,
        "integrity": [{"check": "a check", "passed": True, "detail": "ok"}],
        "writes": {"write_latency": summary, "commit_to_queryable": summary, "transient_retries": 0},
        "reads": summary,
        "lifecycle": {
            "lifecycle_total": summary,
            "per_step": {"incident": summary},
            "transient_retries": 0,
        },
        "concurrency": [
            {
                "concurrency": 2,
                "submitted": 4,
                "committed": 4,
                "failed": 0,
                "wall_s": 2.0,
                "committed_tx_per_s": 2.0,
                "latency": summary,
                "failure_samples": [],
            }
        ],
        "ledger_tamper": {
            "blocks": 5,
            "transactions": 9,
            "genuine_chain": {"ok": True, "blocks": 5},
            "accounting": {
                "client_reported_committed": 9,
                "reported_and_valid_on_ledger": 9,
                "reported_but_missing_from_ledger": 0,
                "reported_but_invalid_on_ledger": 0,
                "ledger_validation_outcomes": {"VALID": 9},
            },
            "tamper_target_block": 2,
            "edit_one_byte_of_a_transaction": {"ok": False, "block": 2, "reason": "x"},
            "edit_and_recompute_that_blocks_data_hash": {"ok": False, "block": 3, "reason": "y"},
        },
    }
    md = bc.render_markdown(report)
    for heading in (
        "Integrity checks",
        "Ledger tamper evidence",
        "Latency",
        "Concurrency",
        "Scope of the claim",
    ):
        assert heading in md
    assert "PASS" in md and "DETECTED at block 2" in md and "DETECTED at block 3" in md
