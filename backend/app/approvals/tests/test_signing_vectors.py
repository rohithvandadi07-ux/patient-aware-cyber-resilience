"""Golden vectors shared with the browser (frontend/src/approvals/signing.test.ts).
Ed25519 is deterministic, so both sides must produce identical messages and signatures."""

from datetime import UTC, datetime

from app.approvals.signing import approval_message, verify_signature

TS = datetime(2026, 10, 19, 10, 0, 0, 123000, tzinfo=UTC)
PUBLIC_KEY = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

PLAIN_ID = "INC-ventilator-01-ab12cd34"
PLAIN_MESSAGE = r'{"chosen_action":"rotate_credentials","decision":"approved","incident_id":"INC-ventilator-01-ab12cd34","policy_rule_id":"approval_high_impact","ts":"2026-10-19T10:00:00.123000Z","v":1}'
PLAIN_SIGNATURE = "wpTWVY1PVVem7mO40vu+Vnmy4TjwAO5DJFtrU5Ov8RjUnwN+DfvCfv0Zr3kCL8zIZqiLyX4DyOL7V/VIEwdrCA=="

UNICODE_ID = "INC-\u00e9-\U0001F600-\x7f"
UNICODE_MESSAGE = r'{"chosen_action":"rotate_credentials","decision":"approved","incident_id":"INC-\u00e9-\ud83d\ude00-\u007f","policy_rule_id":"approval_high_impact","ts":"2026-10-19T10:00:00.123000Z","v":1}'
UNICODE_SIGNATURE = "BYf1jiXJT2NX7Wx6E1Tl39JQuRlekihf9OGTmfTGfHDFG8vvIJDJfGosU+LP/6drx8wbNmNvTXsAgxM72NytDw=="


def message(incident_id):
    return approval_message(incident_id, "rotate_credentials", "approval_high_impact", "approved", TS)


def test_plain_vector():
    assert message(PLAIN_ID).decode() == PLAIN_MESSAGE
    assert verify_signature(PUBLIC_KEY, PLAIN_MESSAGE.encode(), PLAIN_SIGNATURE)


def test_unicode_vector():
    assert message(UNICODE_ID).decode() == UNICODE_MESSAGE
    assert verify_signature(PUBLIC_KEY, UNICODE_MESSAGE.encode(), UNICODE_SIGNATURE)


def test_signature_does_not_verify_for_a_different_message():
    assert not verify_signature(PUBLIC_KEY, UNICODE_MESSAGE.encode(), PLAIN_SIGNATURE)
