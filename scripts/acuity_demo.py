"""Same attack, different patient condition -> different routing.

Runs one real attack flow (from datasets/demo/demo_flows.json) against a device,
runs the agent pipeline, and prints the policy decision. Repeats after the
simulated clock has pushed the patient into HIGH acuity.
"""
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("PACR_API", "http://localhost:8000")
KEY = os.environ.get("PACR_API_KEY")
FLOWS_FILE = "datasets/demo/demo_flows.json"


def call(method, path, body=None):
    headers = {"Content-Type": "application/json"}
    if KEY:
        headers["X-API-Key"] = KEY
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        print(f"!! {method} {path} -> {e.code}: {e.read().decode()[:600]}")
        sys.exit(1)


def find(obj, key):
    if isinstance(obj, dict):
        if key in obj and obj[key] is not None:
            return obj[key]
        for v in obj.values():
            r = find(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find(v, key)
            if r is not None:
                return r
    return None


def patient_for(device_id):
    for p in call("GET", "/patients"):
        if device_id in p["device_ids"]:
            return p
    return None


def pick_attack_flow():
    items = json.load(open(FLOWS_FILE))
    for it in items:
        if "benign" not in it["true_class"].lower():
            return it["true_class"], it["request"]["flows"]
    sys.exit("no attack flow in demo file")


def run_once(label, device_id, true_class, flows):
    p = patient_for(device_id)
    print(f"\n=== {label} ===")
    if p:
        print(f"patient {p['patient_id']} on {device_id}: NEWS2={p['news2_score']} acuity={p['acuity_band']}")
    out = call("POST", "/detections/score-flows", {"device_id": device_id, "flows": flows})
    ids = (out or {}).get("incident_ids") or []
    if not ids:
        print("no incident created; response:", json.dumps(out)[:300])
        return
    iid = ids[0]
    print(f"attack={true_class} -> incident {iid}")
    call("POST", f"/incidents/{iid}/investigate", {})
    dec = call("GET", f"/responses/proposed/{iid}")
    if isinstance(dec, list):
        dec = dec[0] if dec else {}
    print("chosen_action        :", dec.get("chosen_action"))
    print("requires_approval    :", dec.get("requires_human_approval"))
    print("policy_rule_id       :", dec.get("policy_rule_id"))
    print("rationale            :", (dec.get("rationale") or "")[:260])
    trace = call("GET", f"/agents/{iid}")
    print("context.patient_acuity:", find(trace, "patient_acuity"), "| news2:", find(trace, "news2_score"))


def main():
    true_class, flows = pick_attack_flow()
    ecg = "ecg-monitor-01"
    run_once("1. ECG monitor, patient stable", ecg, true_class, flows)

    for _ in range(24):
        p = patient_for(ecg)
        if p["acuity_band"] == "high":
            break
        call("POST", "/patients/clock/advance", {"minutes": 30})
    p = patient_for(ecg)
    print(f"\n(clock advanced; ECG patient now NEWS2={p['news2_score']} acuity={p['acuity_band']}, minute {p['simulated_minute']})")
    run_once("2. ECG monitor, same attack, patient deteriorating", ecg, true_class, flows)

    run_once("3. Ventilator, patient already HIGH acuity", "ventilator-01", true_class, flows)


main()
