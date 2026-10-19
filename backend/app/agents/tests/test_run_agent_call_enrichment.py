from types import SimpleNamespace

from pydantic import BaseModel

from app.agents.base import run_agent_call
from app.agents.llm_client import MockLLMClient


class _Out(BaseModel):
    incident_id: str
    tag: str | None = None


class _Recorder:
    def __init__(self):
        self.success = []

    def record_success(self, **kw):
        self.success.append(kw)

    def record_failure(self, **kw):
        pass


def _run(ground):
    recorder = _Recorder()
    toolkit = SimpleNamespace(
        trace_recorder=recorder,
        incident_repository=SimpleNamespace(update_status=lambda *a, **k: None),
    )
    out = run_agent_call(
        client=MockLLMClient(responses=['{"incident_id": "i1"}']),
        toolkit=toolkit,
        agent_name="test_agent",
        incident_id="i1",
        prompt="p",
        output_schema=_Out,
        input_payload={},
        stall_status="stalled",
        ground=ground,
    )
    return out, recorder


def test_enrichment_without_corrections_is_still_used_and_traced():
    out, recorder = _run(lambda o: (o.model_copy(update={"tag": "enriched"}), []))
    assert out.tag == "enriched"
    assert recorder.success[0]["output_payload"]["tag"] == "enriched"


def test_no_change_keeps_the_raw_output():
    out, recorder = _run(lambda o: (o, []))
    assert out.tag is None
    assert "grounding_corrections" not in recorder.success[0]["output_payload"]


def test_corrections_are_still_recorded_with_the_raw_output():
    out, recorder = _run(lambda o: (o.model_copy(update={"tag": "fixed"}), ["tag was wrong"]))
    payload = recorder.success[0]["output_payload"]
    assert out.tag == "fixed"
    assert payload["grounding_corrections"] == ["tag was wrong"]
    assert payload["agent_output_before_grounding"]["tag"] is None
