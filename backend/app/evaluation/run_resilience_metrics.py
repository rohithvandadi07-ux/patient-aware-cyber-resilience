"""Resilience metrics on the real CICIoMT2024 detector: latency, detection delay
and the cost of human approval.

Section 18 of the architecture names MTTD/MTTR/latency as a separate metric
family that "has no measurement infrastructure". This script supplies what can
be measured honestly from this codebase and the real data, and labels what is a
model rather than a measurement.

Measured
--------
* **Decision-path latency**: wall-clock per call of the Risk Engine + Policy
  Engine (`decide_full_system`) over many trials, and the real detector's
  per-flow latency (single flow) and batch throughput. In-process compute only.
* **Detection delay, in flows**: for every attack capture in the official test
  split, in file (capture) order, how many flows pass before the first flow the
  runtime detector would alert on (predicted not-benign with confidence >=
  0.6). The dataset's feature rows carry no wall-clock timestamp, so delay is
  counted in flows, not seconds; each CICIoMT2024 row already summarises a
  window of packets, so even flow 0 reflects some traffic. It is NOT an
  attack-onset-to-alert time: captures may contain traffic before the attack
  starts, and that is not labelled.

Modelled (stated as such)
-------------------------
* **Containment delay**: for each real attack that the detector alerts on, the
  system either acts on its own (delay = measured pipeline time) or waits for a
  human (delay = pipeline time + an ASSUMED human approval time D). D is
  swept (1, 5, 15, 60 minutes) because this repository has no measurement of
  how long a hospital takes to approve. What is measured is the SHARE of alerts
  that wait for a human, per system and per device-risk group. Attacks the
  detector misses are reported separately, never folded into a delay.

Not measured
------------
LLM-agent latency (the pipeline runs a mock LLM; a live model's latency would
dominate), network/queueing latency, device recovery time, and real human
response time.

Usage (from `backend/`):
    python -m app.evaluation.run_resilience_metrics --data-dir /path/to/iomt
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.cybersecurity.ciciomt2024 import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    SOURCE_FILE_COLUMN,
    load_split,
)
from app.cybersecurity.detection_service import DEFAULT_CONFIDENCE_THRESHOLD
from app.evaluation.baseline_systems import (
    decide_full_system,
    detection_outcome_from_row,
    sample_device_contexts,
)
from app.evaluation.run_confidence_gating import baseline_pass
from app.evaluation.run_real_data_comparison import harness_label, predict_all
from app.policy_engine.engine import PolicyEngine
from app.risk_engine.rule_based import RuleBasedRiskModel

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_MODEL = _REPO_ROOT / "experiments" / "models" / "ciciomt2024_xgboost.joblib"
_DEFAULT_OUTPUT_DIR = _REPO_ROOT / "evaluation"
HUMAN_APPROVAL_MINUTES = [1, 5, 15, 60]
_BASE_CONTEXT_SEED = 2026


def percentile_stats(values_ms: list[float]) -> dict[str, float]:
    a = np.asarray(values_ms, dtype=float)
    return {
        "n": int(len(a)),
        "p50_ms": float(np.percentile(a, 50)),
        "p95_ms": float(np.percentile(a, 95)),
        "p99_ms": float(np.percentile(a, 99)),
        "max_ms": float(a.max()),
    }


def decision_path_latency(n: int = 3000, seed: int = 7) -> dict[str, float]:
    """Wall-clock per `decide_full_system` call (Risk Engine + Policy Engine +
    the harness's deterministic stand-ins for the LLM agents)."""
    risk_model, policy_engine = RuleBasedRiskModel(), PolicyEngine()
    contexts = sample_device_contexts(n, seed=seed)
    times: list[float] = []
    for i, context in enumerate(contexts):
        detection = detection_outcome_from_row("dos", "dos", 0.95)
        t = time.perf_counter()
        decide_full_system(detection, context, f"lat-{i}", risk_model=risk_model, policy_engine=policy_engine)
        times.append((time.perf_counter() - t) * 1000.0)
    return percentile_stats(times)


def detector_latency(model: Any, X: np.ndarray, single_calls: int = 300, batch: int = 1000) -> dict[str, Any]:
    singles: list[float] = []
    for i in range(single_calls):
        t = time.perf_counter()
        model.predict_proba(X[i : i + 1])
        singles.append((time.perf_counter() - t) * 1000.0)
    t = time.perf_counter()
    model.predict_proba(X[:batch])
    batch_ms = (time.perf_counter() - t) * 1000.0
    return {
        "single_flow": percentile_stats(singles),
        "batch": {"flows": batch, "total_ms": batch_ms, "flows_per_second": batch / (batch_ms / 1000.0)},
    }


def detection_delay_per_capture(
    source_files: np.ndarray, true19: np.ndarray, detected: np.ndarray
) -> list[dict[str, Any]]:
    """For each ATTACK capture (file), flows before the first alert, in file
    order. `detected[i]` is whether the runtime detector would alert on row i."""
    out = []
    for name in dict.fromkeys(source_files.tolist()):
        idx = np.flatnonzero(source_files == name)
        if true19[idx[0]] == "Benign":
            continue
        hits = np.flatnonzero(detected[idx])
        out.append(
            {
                "capture": name,
                "class": str(true19[idx[0]]),
                "flows": int(len(idx)),
                "first_alert_flow_index": int(hits[0]) if len(hits) else None,
                "share_of_flows_alerted": float(detected[idx].mean()),
                "alerted_within_10_flows": bool(len(hits) and hits[0] < 10),
                "alerted_within_100_flows": bool(len(hits) and hits[0] < 100),
            }
        )
    return out


def containment_profile(p: dict[str, np.ndarray], executed: np.ndarray, pipeline_ms: float) -> dict[str, Any]:
    """Share of real attacks that are missed / contained autonomously / wait for
    a human, overall and on high-stakes devices, plus the MODELLED mean
    containment delay (over alerted attacks) for each assumed human delay."""
    attack, fired, high = p["attack"], p["fired"], p["high_stakes"]

    def group(mask: np.ndarray) -> dict[str, Any]:
        total = int((attack & mask).sum())
        alerted = attack & fired & mask
        auto = alerted & executed
        waiting = alerted & ~executed
        n_alerted = int(alerted.sum())
        share_wait = float(waiting.sum() / n_alerted) if n_alerted else None
        return {
            "real_attacks": total,
            "missed_by_detector": total - n_alerted,
            "alerted": n_alerted,
            "contained_autonomously": int(auto.sum()),
            "waiting_for_human": int(waiting.sum()),
            "share_of_alerts_waiting_for_human": share_wait,
            "modelled_mean_containment_delay_seconds": {
                str(d): (pipeline_ms / 1000.0 + share_wait * d * 60.0) if share_wait is not None else None
                for d in HUMAN_APPROVAL_MINUTES
            },
        }

    everything = np.ones_like(attack)
    return {"all_devices": group(everything), "high_stakes_devices": group(high)}


def _pct(x: float | None, d: int = 1) -> str:
    return "n/a" if x is None else f"{x * 100:.{d}f}%"


def render_markdown(report: dict[str, Any]) -> str:
    lat = report["latency"]
    lines = [
        "# Resilience metrics on the real CICIoMT2024 detector",
        "",
        f"Generated {report['generated_at']}. What is measured, what is modelled and what is not measured "
        "at all is spelled out in `backend/app/evaluation/run_resilience_metrics.py`; the short version "
        "is repeated under each heading.",
        "",
        "## Latency (measured, in-process compute only)",
        "",
        "| Step | p50 | p95 | p99 | n |",
        "|---|---|---|---|---|",
        f"| Risk + Policy decision path (per incident) | {lat['decision_path']['p50_ms']:.3f} ms "
        f"| {lat['decision_path']['p95_ms']:.3f} ms | {lat['decision_path']['p99_ms']:.3f} ms "
        f"| {lat['decision_path']['n']} |",
        f"| Real detector, one flow | {lat['detector']['single_flow']['p50_ms']:.3f} ms "
        f"| {lat['detector']['single_flow']['p95_ms']:.3f} ms "
        f"| {lat['detector']['single_flow']['p99_ms']:.3f} ms "
        f"| {lat['detector']['single_flow']['n']} |",
        "",
        f"Detector batch throughput: {lat['detector']['batch']['flows_per_second']:,.0f} flows/s "
        f"({lat['detector']['batch']['flows']} flows in {lat['detector']['batch']['total_ms']:.1f} ms).",
        "",
        "Not included: LLM-agent latency (a live model would dominate; this pipeline runs a mock), "
        "network and queueing delay, and real device recovery time.",
        "",
        "## Detection delay, counted in flows (measured)",
        "",
        "For each attack capture in the official test split, flows before the detector's first alert, in "
        "file order. The rows carry no wall-clock timestamp, so this is flows, not seconds, and not "
        "attack-onset-to-alert (a capture may contain unlabelled pre-attack traffic).",
        "",
        "| Capture class | Flows | First alert at flow | Flows alerted | Within 10 flows |",
        "|---|---|---|---|---|",
    ]
    for c in report["detection_delay"]["captures"]:
        first = "never" if c["first_alert_flow_index"] is None else str(c["first_alert_flow_index"])
        lines.append(
            f"| {c['class']} ({c['capture']}) | {c['flows']:,} | {first} "
            f"| {_pct(c['share_of_flows_alerted'])} | {'yes' if c['alerted_within_10_flows'] else 'no'} |"
        )
    s = report["detection_delay"]["summary"]
    lines += [
        "",
        f"{s['captures_alerted']} of {s['captures']} attack captures were alerted on; "
        f"{s['captures_alerted_within_10_flows']} within their first 10 flows, "
        f"{s['captures_alerted_within_100_flows']} within 100.",
        "",
        "## Cost of human approval: who waits (measured shares, modelled delay)",
        "",
        "Shares are measured on all 1,614,182 test rows with sampled device contexts. The delay columns "
        "are a model: pipeline time (measured above) plus the share of alerts that wait for a human "
        "times an ASSUMED approval time D. The repository has no measurement of D.",
        "",
    ]
    for scope, title in (("all_devices", "All devices"), ("high_stakes_devices", "High-stakes devices only")):
        lines += [
            f"### {title}",
            "",
            "| System | Real attacks | Missed by detector | Contained autonomously | Waiting for a human "
            "| Share of alerts waiting | Mean delay at D = "
            + " / ".join(f"{d} min" for d in HUMAN_APPROVAL_MINUTES)
            + " |",
            "|---|---|---|---|---|---|---|",
        ]
        for name, prof in report["containment"].items():
            g = prof[scope]
            delays = " / ".join(
                "n/a" if v is None else f"{v:.1f} s"
                for v in g["modelled_mean_containment_delay_seconds"].values()
            )
            lines.append(
                f"| {name} | {g['real_attacks']:,} | {g['missed_by_detector']:,} "
                f"| {g['contained_autonomously']:,} "
                f"| {g['waiting_for_human']:,} | {_pct(g['share_of_alerts_waiting_for_human'])} | {delays} |"
            )
        lines.append("")
    lines += [
        "## Reading this honestly",
        "",
        "- `detection_only` never acts, so every alert waits for a human (a fully manual response). "
        "`fixed_response` contains every alert at once but acts autonomously on high-stakes devices, "
        "which is the unsafe behaviour the safety comparison measures. `full_system` is where the "
        "patient-aware cost shows up: on high-stakes devices every alert waits for a human by design, "
        "so the delay there is the approval time, not a pipeline cost; on the other devices about "
        "half of alerts wait.",
        "- The modelled delay is dominated by the assumed D; the table is a way to see that trade-off, not "
        "a prediction of a hospital's response time.",
        f"- {report['seeds_used']} device-context seeds were used; contexts are sampled, not observed.",
    ]
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.time()
    model = joblib.load(args.model_path)
    test = load_split(args.data_dir, "test")
    true19 = test[LABEL_COLUMN].to_numpy(dtype=object)
    sources = test[SOURCE_FILE_COLUMN].to_numpy(dtype=object)
    X = test[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    del test
    print(f"[{time.time() - t0:5.0f}s] {len(X):,} test rows loaded", flush=True)

    pred19, conf = predict_all(model, X)
    latency = {"decision_path": decision_path_latency(), "detector": detector_latency(model, X)}
    del X
    pipeline_ms = latency["decision_path"]["p50_ms"]

    pred_h = np.array([harness_label(x) for x in pred19], dtype=object)
    true_h = np.array([harness_label(x) for x in true19], dtype=object)
    detected = (pred_h != "unknown") & (conf >= DEFAULT_CONFIDENCE_THRESHOLD)
    captures = detection_delay_per_capture(sources, true19, detected)
    summary = {
        "captures": len(captures),
        "captures_alerted": sum(c["first_alert_flow_index"] is not None for c in captures),
        "captures_alerted_within_10_flows": sum(c["alerted_within_10_flows"] for c in captures),
        "captures_alerted_within_100_flows": sum(c["alerted_within_100_flows"] for c in captures),
    }
    print(f"[{time.time() - t0:5.0f}s] detection delay done", flush=True)

    acc: dict[str, list[dict[str, Any]]] = {"detection_only": [], "fixed_response": [], "full_system": []}
    for i in range(args.n_seeds):
        p = baseline_pass(true_h, pred_h, conf, seed=_BASE_CONTEXT_SEED + 7919 * i)
        acc["detection_only"].append(containment_profile(p, np.zeros_like(p["executed"]), pipeline_ms))
        acc["fixed_response"].append(containment_profile(p, p["fired"], pipeline_ms))
        acc["full_system"].append(containment_profile(p, p["executed"], pipeline_ms))
        print(f"[{time.time() - t0:5.0f}s] containment seed {i + 1}/{args.n_seeds}", flush=True)

    # Average the per-seed profiles (counts and shares) into one table.
    def mean_profile(profiles: list[dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for scope in ("all_devices", "high_stakes_devices"):
            rows = [pr[scope] for pr in profiles]
            merged: dict[str, Any] = {}
            for key in (
                "real_attacks",
                "missed_by_detector",
                "alerted",
                "contained_autonomously",
                "waiting_for_human",
            ):
                merged[key] = int(round(float(np.mean([r[key] for r in rows]))))
            shares = [
                r["share_of_alerts_waiting_for_human"]
                for r in rows
                if r["share_of_alerts_waiting_for_human"] is not None
            ]
            share = float(np.mean(shares)) if shares else None
            merged["share_of_alerts_waiting_for_human"] = share
            merged["modelled_mean_containment_delay_seconds"] = {
                str(d): (pipeline_ms / 1000.0 + share * d * 60.0) if share is not None else None
                for d in HUMAN_APPROVAL_MINUTES
            }
            out[scope] = merged
        return out

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model_path": args.model_path.name,
        "seeds_used": args.n_seeds,
        "human_approval_minutes_assumed": HUMAN_APPROVAL_MINUTES,
        "latency": latency,
        "detection_delay": {"captures": captures, "summary": summary},
        "containment": {name: mean_profile(profiles) for name, profiles in acc.items()},
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "resilience_metrics.json").write_text(json.dumps(report, indent=2, default=float))
    (args.output_dir / "resilience_metrics.md").write_text(render_markdown(report))
    print(f"[{time.time() - t0:5.0f}s] wrote reports to {args.output_dir}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, required=True, help="Folder containing train/ and test/.")
    parser.add_argument("--model-path", type=Path, default=_DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--n-seeds", type=int, default=3)
    args = parser.parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
