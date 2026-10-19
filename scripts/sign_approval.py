#!/usr/bin/env python3
"""Generate an approver keypair and submit Ed25519-signed approvals.

  python scripts/sign_approval.py keygen dr-alice
  python scripts/sign_approval.py approve --identity dr-alice --incident INC-ventilator-01-xxxx
  python scripts/sign_approval.py approve --identity dr-alice --incident INC-... --decision rejected

Private keys live in ~/.pacr/keys/<identity>.key (mode 600), outside the repo.
Set PACR_API_KEY if the API has auth enabled. Run with the backend virtualenv
(needs the `cryptography` package).
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.approvals.signing import approval_message  # noqa: E402

KEY_DIR = Path.home() / ".pacr" / "keys"


def key_path(identity: str) -> Path:
    return KEY_DIR / f"{identity}.key"


def keygen(identity: str) -> None:
    path = key_path(identity)
    if path.exists():
        sys.exit(f"{path} already exists; refusing to overwrite a private key")
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(raw_private).decode())
    path.chmod(0o600)
    print(f"private key written to {path}")
    print("register the public key with the server:")
    print(f"  APPROVER_PUBLIC_KEYS={identity}={base64.b64encode(raw_public).decode()}")


def api(base: str, method: str, path: str, body=None):
    headers = {"Content-Type": "application/json"}
    if os.environ.get("PACR_API_KEY"):
        headers["X-API-Key"] = os.environ["PACR_API_KEY"]
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or "null")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw


def approve(args) -> None:
    path = key_path(args.identity)
    if not path.exists():
        sys.exit(f"no private key at {path}; run: keygen {args.identity}")
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))

    status, decision = api(args.base, "GET", f"/responses/proposed/{args.incident}")
    if status != 200:
        sys.exit(f"no pending decision for {args.incident}: HTTP {status} {decision}")
    print(f"pending: {decision['chosen_action']} (rule {decision['policy_rule_id']}, "
          f"human approval required: {decision['requires_human_approval']})")

    timestamp = datetime.now(UTC)
    message = approval_message(
        args.incident, decision["chosen_action"], decision["policy_rule_id"], args.decision, timestamp
    )
    signature = base64.b64encode(private.sign(message)).decode()
    status, result = api(args.base, "POST", "/responses/executed", {
        "incident_id": args.incident,
        "approval": {
            "incident_id": args.incident,
            "approver_identity": args.identity,
            "decision": args.decision,
            "timestamp": timestamp.isoformat(),
            "notes": args.notes,
            "signature": signature,
        },
    })
    print(f"HTTP {status}")
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("keygen")
    gen.add_argument("identity")
    app = sub.add_parser("approve")
    app.add_argument("--identity", required=True)
    app.add_argument("--incident", required=True)
    app.add_argument("--decision", choices=["approved", "rejected"], default="approved")
    app.add_argument("--notes", default="signed via sign_approval.py")
    app.add_argument("--base", default="http://localhost:8000")
    args = parser.parse_args()
    keygen(args.identity) if args.command == "keygen" else approve(args)


if __name__ == "__main__":
    main()
