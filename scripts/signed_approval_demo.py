"""M6 live demo: attack the approval gate, then approve properly.

Needs: APPROVER_PUBLIC_KEYS / REQUIRE_SIGNED_APPROVALS set on the backend and
a key made with `python scripts/sign_approval.py keygen dr-alice`.
"""
import base64
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.approvals.signing import approval_message  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
IDENTITY = "dr-alice"
KEY_FILE = Path.home() / ".pacr" / "keys" / f"{IDENTITY}.key"


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def cred_version():
    return call("GET", "/devices/ventilator-01")[1].get("credential_version")


iid = f"SIGNDEMO-{int(time.time())}"
action = "rotate_credentials"
call("POST", "/incidents", {"incident_id": iid, "device_id": "ventilator-01", "attack_type": "mqtt_based",
                            "evidence_ref": f"ev-{iid}", "timestamp": datetime.now(UTC).isoformat()})
call("POST", "/responses/proposed", {
    "risk_score": {"incident_id": iid, "cyber_risk": 0.8, "clinical_risk": 0.5,
                   "response_impact": {action: "high"}, "explanation": "scripted"},
    "proposed_response": {"incident_id": iid, "candidate_actions": [{"action_category": action, "description": "d"}],
                          "security_benefit": {action: 0.7}, "clinical_impact": {action: "high"},
                          "recommended_action": action, "rationale": "scripted"},
    "context": {"incident_id": iid, "device_criticality": "high", "patient_dependency": True,
                "clinical_impact_level": "high", "safety_constraints": []},
})
_, decision = call("GET", f"/responses/proposed/{iid}")
print(f"incident {iid}: pending {decision['chosen_action']} via {decision['policy_rule_id']}")
print(f"ventilator credential version before: v{cred_version()}\n")


def signed(key, decision_value="approved", identity=IDENTITY):
    ts = datetime.now(UTC)
    msg = approval_message(iid, decision["chosen_action"], decision["policy_rule_id"], decision_value, ts)
    return {"incident_id": iid, "approver_identity": identity, "decision": decision_value,
            "timestamp": ts.isoformat(), "signature": base64.b64encode(key.sign(msg)).decode()}


def attempt(label, approval):
    status, body = call("POST", "/responses/executed", {"incident_id": iid, "approval": approval})
    detail = body.get("detail") if isinstance(body, dict) else body
    print(f"{label}\n    -> HTTP {status} {detail if status >= 300 else 'executed_by=' + body['executed_by']}")


attempt("1. unsigned approval claiming to be dr-alice",
        {"incident_id": iid, "approver_identity": IDENTITY, "decision": "approved",
         "timestamp": datetime.now(UTC).isoformat()})
attempt("2. forged: signed with a random key, claiming to be dr-alice", signed(Ed25519PrivateKey.generate()))
status, body = call("POST", f"/incidents/{iid}/investigate", {"auto_approve": True})
print(f"3. auto_approve to skip the human\n    -> HTTP {status} {body.get('detail') if isinstance(body, dict) else body}")
print(f"\nstill pending after the attacks: {call('GET', f'/responses/proposed/{iid}')[0] == 200}")
print(f"credential version after the attacks: v{cred_version()}\n")

if not KEY_FILE.exists():
    sys.exit(f"no key at {KEY_FILE}; run: python scripts/sign_approval.py keygen {IDENTITY}")
real = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY_FILE.read_text().strip()))
attempt("4. genuine signed approval by dr-alice", signed(real))
print(f"\nventilator credential version after: v{cred_version()}")
