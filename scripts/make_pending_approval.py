"""Create an incident with a pending, approval-required decision (no LLM) so it can be approved in the console."""
import json
import time
import urllib.request
from datetime import UTC, datetime

BASE = "http://localhost:8000"


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read() or "null")


iid = f"BROWSER-DEMO-{int(time.time()) % 100000}"
action = "rotate_credentials"
call("POST", "/incidents", {"incident_id": iid, "device_id": "ventilator-01", "attack_type": "mqtt_based",
                            "evidence_ref": f"ev-{iid}", "timestamp": datetime.now(UTC).isoformat()})
call("POST", "/responses/proposed", {
    "risk_score": {"incident_id": iid, "cyber_risk": 0.8, "clinical_risk": 0.5,
                   "response_impact": {action: "high"}, "explanation": "scripted for the browser demo"},
    "proposed_response": {"incident_id": iid, "candidate_actions": [{"action_category": action, "description": "d"}],
                          "security_benefit": {action: 0.7}, "clinical_impact": {action: "high"},
                          "recommended_action": action, "rationale": "scripted for the browser demo"},
    "context": {"incident_id": iid, "device_criticality": "high", "patient_dependency": True,
                "clinical_impact_level": "high", "safety_constraints": []},
})
print("\nOpen this incident in the console:", iid, "\n")
