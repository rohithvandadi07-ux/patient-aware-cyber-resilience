"""M4 live demo: run resilience actions against modelled device state.

Bypasses the LLM: posts a policy decision with a chosen action, executes it
(with a clinician approval if the policy requires one) and prints the
device's modelled state afterwards. Steps marked EXPECT 409 must be refused
because their precondition is not met.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
RUN = str(int(time.time()))[-6:]


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def now():
    return datetime.now(timezone.utc).isoformat()


def device_state(device_id):
    _, devices = call("GET", "/devices")
    d = next(x for x in devices if x["device_id"] == device_id)
    return (
        f"op={d['operational_state']} net={d['network_state']} "
        f"sessions={len(d.get('active_sessions', []))} cred=v{d.get('credential_version')} "
        f"backup={'active' if d.get('backup_active') else 'available' if d.get('backup_available') else 'none'} "
        f"serving={d.get('serving_unit')} standby={d.get('standby_unit_id')}"
    )


def step(n, device_id, criticality, patient_dep, action, expect_409=False):
    iid = f"demo-{RUN}-{n}"
    print(f"\n[{n}] {device_id}: {action}" + ("   (EXPECT 409)" if expect_409 else ""))
    print("    before:", device_state(device_id))

    s, r = call("POST", "/incidents", {
        "incident_id": iid, "device_id": device_id, "attack_type": "mqtt_based",
        "evidence_ref": f"demo-evidence-{iid}", "timestamp": now(),
    })
    if s >= 300:
        print("    incident FAILED", s, r); return

    impact = "high" if patient_dep else "medium"
    proposal = {
        "risk_score": {
            "incident_id": iid, "cyber_risk": 0.8, "clinical_risk": 0.5,
            "response_impact": {action: impact},
            "explanation": "Scripted demo input; the LLM is bypassed.",
        },
        "proposed_response": {
            "incident_id": iid,
            "candidate_actions": [{"action_category": action, "description": f"Demo: {action}"}],
            "security_benefit": {action: 0.7},
            "clinical_impact": {action: impact},
            "recommended_action": action,
            "rationale": "Scripted demo input.",
        },
        "context": {
            "incident_id": iid, "device_criticality": criticality,
            "patient_dependency": patient_dep, "clinical_impact_level": impact,
            "safety_constraints": [],
        },
        "detection_confidence": 0.9,
    }
    s, r = call("POST", "/responses/proposed", proposal)
    if s >= 300:
        print("    propose FAILED", s, json.dumps(r)[:400]); return
    routing = {k: v for k, v in (r or {}).items() if k in ("routing", "route", "rule_triggered", "reason", "requires_approval")}
    print("    policy:", json.dumps(routing) if routing else json.dumps(r)[:300])

    s, r = call("POST", "/responses/executed", {"incident_id": iid})
    if s >= 300 and "approv" in json.dumps(r).lower():
        print("    approval required -> approving as demo-clinician")
        s, r = call("POST", "/responses/executed", {
            "incident_id": iid,
            "approval": {"incident_id": iid, "approver_identity": "demo-clinician",
                         "decision": "approved", "timestamp": now(), "notes": "demo"},
        })
    verdict = "OK" if s < 300 else f"HTTP {s}"
    ok = (s == 409) if expect_409 else (s < 300)
    print(f"    execute: {verdict} {'(as expected)' if ok else '(UNEXPECTED)'}")
    if s >= 300:
        print("    detail:", json.dumps(r)[:300])
    print("    after: ", device_state(device_id))


V, E, P = "ventilator-01", "ecg-monitor-01", "infusion-pump-01"
step(1, V, "high", True, "revoke_session")
step(2, V, "high", True, "revoke_session", expect_409=True)   # no sessions left
step(3, V, "high", True, "rotate_credentials")
step(4, V, "high", True, "activate_backup")
step(5, V, "high", True, "failover")
step(6, V, "high", True, "failover", expect_409=True)         # already failed over
step(7, E, "medium", True, "activate_backup")
step(8, P, "medium", False, "revoke_session")
step(9, P, "medium", False, "activate_backup", expect_409=True)  # pump has no backup
print("\nDone. Open the Fleet page: the Response state rows show the same final state.")
