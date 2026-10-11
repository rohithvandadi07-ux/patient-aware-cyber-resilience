"""Unit tests for SubprocessFabricClient's pure parsing helpers -- the
actual subprocess invocation against a live network is exercised by the
Phase 8 integration test, not here (these need no network, no binaries)."""

from app.blockchain.fabric_client import (
    _TRANSIENT_ERROR_PATTERN,
    _args_json,
    _parse_invoke_result,
)


def test_args_json_matches_peer_cli_arg_shape():
    assert _args_json(["Ping", "hello"]) == '{"Args": ["Ping", "hello"]}'


def test_parse_invoke_result_extracts_tx_id_and_payload_from_real_peer_cli_output():
    # Mirrors a real line as logged by `peer chaincode invoke` (see
    # blockchain/chaincode/README.md): a JSON payload, embedded as an
    # escaped string inside the log line's own double quotes.
    inner_json = '{"incidentId":"INC-1","deviceId":"dev-1","recordedTxId":"abc123"}'
    escaped = inner_json.replace('"', '\\"')
    output = (
        "INFO chaincodeCmd chaincodeInvokeOrQuery -> Chaincode invoke successful. "
        f'result: status:200 payload:"{escaped}" '
    )

    result = _parse_invoke_result(output)

    assert result.tx_id == "abc123"
    assert result.payload["incidentId"] == "INC-1"
    assert result.payload["deviceId"] == "dev-1"


def test_parse_invoke_result_falls_back_to_txid_log_line_when_payload_has_no_recordedtxid():
    output = 'ClientWait -> txid [deadbeef123] committed with status (VALID) at 127.0.0.1:7051'

    result = _parse_invoke_result(output)

    assert result.tx_id == "deadbeef123"
    assert result.payload == {}


def test_parse_invoke_result_handles_completely_unparseable_output_without_raising():
    result = _parse_invoke_result("some unrelated log noise")

    assert result.tx_id == ""
    assert result.payload == {}


def test_transient_error_pattern_matches_the_known_endorsement_race_message():
    message = (
        "Error: endorsement failure during invoke. response: status:500 "
        "message:\"incident 'INC-1' has no recordIncident entry -- call recordIncident first\""
    )
    assert _TRANSIENT_ERROR_PATTERN.search(message)


def test_transient_error_pattern_does_not_match_an_unrelated_rejection():
    message = "Error: chaincode install failed with status: 500 - already successfully installed"
    assert _TRANSIENT_ERROR_PATTERN.search(message) is None
