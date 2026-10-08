"""Command-line interface for the IoMT simulator."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from backend.app.domain.ids import IdFactory
from iomt_simulator.hospital import SmartHospital
from iomt_simulator.scenarios.library import SCENARIOS, export_all, get_scenario
from iomt_simulator.scenarios.spec import ScenarioSpec

app = typer.Typer(help="Simulated smart-hospital IoMT environment.", no_args_is_help=True)
console = Console()


def _load(scenario: str) -> ScenarioSpec:
    path = Path(scenario)
    if path.exists():
        return ScenarioSpec.from_yaml(path)
    return get_scenario(scenario)


@app.command("list")
def list_scenarios() -> None:
    """List built-in scenarios."""
    table = Table(title="Built-in scenarios")
    table.add_column("id", style="cyan")
    table.add_column("ticks", justify="right")
    table.add_column("attacks", justify="right")
    table.add_column("description")
    for name in sorted(SCENARIOS):
        s = get_scenario(name)
        table.add_row(
            name, str(s.total_ticks), str(len(s.attack_specs)), s.description[:70] + "..."
        )
    console.print(table)


@app.command("export")
def export(target: str = "configs/scenarios") -> None:
    """Export all built-in scenarios to YAML."""
    written = export_all(target)
    for p in written:
        console.print(f"[green]wrote[/green] {p}")


@app.command("run")
def run(
    scenario: str = typer.Option("baseline_normal", "--scenario", "-s"),
    ticks: int | None = typer.Option(None, "--ticks", "-t"),
    out: str | None = typer.Option(None, "--out", "-o", help="Write events to JSONL"),
    summary_only: bool = typer.Option(False, "--summary-only"),
) -> None:
    """Run a scenario and optionally dump its event stream."""
    spec = _load(scenario)
    hospital = SmartHospital(scenario=spec, ids=IdFactory(deterministic=True))
    n = ticks or spec.total_ticks
    events = hospital.run(n)

    console.print_json(data=hospital.summary())
    if not summary_only:
        table = Table(title="Device states")
        for col in ("device", "type", "criticality", "op state", "net", "alarm"):
            table.add_column(col)
        for did in sorted(hospital.devices):
            d = hospital.devices[did]
            table.add_row(
                did,
                d.profile.device_type.value,
                d.profile.criticality.value,
                d.state.operational_state.value,
                d.state.network_state.value,
                d.state.alarm_reason or "-",
            )
        console.print(table)

    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev.model_dump(mode="json"), separators=(",", ":")) + "\n")
        console.print(f"[green]wrote[/green] {len(events)} events -> {path}")


if __name__ == "__main__":
    app()
