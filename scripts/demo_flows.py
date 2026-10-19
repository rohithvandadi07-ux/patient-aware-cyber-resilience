#!/usr/bin/env python3
"""Build a small demo-flow file from the CICIoMT2024 test CSVs, then replay it
through the running backend's POST /detections/score-flows (real 45-feature XGBoost).

  python scripts/demo_flows.py build --data-dir ~/Documents/S5/hpc/iomt
  python scripts/demo_flows.py replay
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

DEVICES = ["infusion-pump-01", "ventilator-01", "ecg-monitor-01"]
DEFAULT_OUT = Path("datasets/demo/demo_flows.json")


def build(data_dir: Path, per_class: int, benign: int, out: Path) -> None:
    files = sorted((data_dir / "test").glob("*_test.pcap.csv"))
    if not files:
        sys.exit(f"no *_test.pcap.csv files under {data_dir / 'test'}")
    entries, i = [], 0
    for f in files:
        name = f.name.replace("_test.pcap.csv", "")
        n = benign if name == "Benign" else per_class
        df = pd.read_csv(f, nrows=20000)
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        df = df.sample(n=min(n, len(df)), random_state=42)
        for row in df.to_dict(orient="records"):
            flow = {k: float(v) for k, v in row.items()}
            entries.append(
                {"true_class": name, "request": {"device_id": DEVICES[i % 3], "flows": [flow]}}
            )
            i += 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries))
    print(f"wrote {len(entries)} flows from {len(files)} classes to {out}")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _post(url: str, body: dict):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    return json.load(urllib.request.urlopen(req))


def replay(api: str, path: Path) -> None:
    entries = json.loads(path.read_text())
    match = total = detections = 0
    for n, e in enumerate(entries):
        resp = _post(f"{api}/detections/score-flows", e["request"])
        if n == 0:
            print("first response, raw:", json.dumps(resp)[:600])
        verdicts = resp if isinstance(resp, list) else (resp.get("verdicts") or resp.get("results") or [])
        for v in verdicts:
            total += 1
            if _norm(v["predicted_class"]) == _norm(e["true_class"]):
                match += 1
            if v.get("detection"):
                detections += 1
        if verdicts:
            v = verdicts[0]
            print(f"{e['true_class']:<28} -> {v['predicted_class']:<28} conf={v['confidence']:.2f}")
    print(f"\nflows scored: {total}, class matches: {match}, detections raised: {detections}")
    incidents = json.load(urllib.request.urlopen(f"{api}/incidents"))
    print(f"incidents now in the system: {len(incidents)}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--data-dir", type=Path, required=True)
    b.add_argument("--per-class", type=int, default=3)
    b.add_argument("--benign", type=int, default=10)
    b.add_argument("--out", type=Path, default=DEFAULT_OUT)
    r = sub.add_parser("replay")
    r.add_argument("--api", default="http://localhost:8000")
    r.add_argument("--file", type=Path, default=DEFAULT_OUT)
    a = p.parse_args()
    if a.cmd == "build":
        build(a.data_dir.expanduser(), a.per_class, a.benign, a.out)
    else:
        replay(a.api, a.file)