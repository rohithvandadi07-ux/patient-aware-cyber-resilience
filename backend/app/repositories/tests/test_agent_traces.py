from app.repositories.agent_traces import AgentTraceRecorder


def test_record_success_stores_input_and_output():
    recorder = AgentTraceRecorder()
    trace = recorder.record_success(
        incident_id="incident-1",
        agent_name="investigation",
        input_payload={"incident_id": "incident-1"},
        output_payload={"evidence": ["log line 1"]},
    )
    assert trace.succeeded is True
    assert trace.error is None
    assert trace.input_payload == {"incident_id": "incident-1"}
    assert trace.output_payload == {"evidence": ["log line 1"]}


def test_record_failure_stores_error_and_no_output():
    recorder = AgentTraceRecorder()
    trace = recorder.record_failure(
        incident_id="incident-1",
        agent_name="investigation",
        input_payload={"incident_id": "incident-1"},
        error="validation failed twice",
    )
    assert trace.succeeded is False
    assert trace.output_payload is None
    assert trace.error == "validation failed twice"


def test_list_for_incident_filters_by_incident_id():
    recorder = AgentTraceRecorder()
    recorder.record_success("incident-1", "investigation", {}, {})
    recorder.record_success("incident-2", "investigation", {}, {})
    recorder.record_success("incident-1", "threat_reasoning", {}, {})
    traces = recorder.list_for_incident("incident-1")
    assert len(traces) == 2
    assert {t.agent_name for t in traces} == {"investigation", "threat_reasoning"}


def test_list_for_agent_filters_by_agent_name():
    recorder = AgentTraceRecorder()
    recorder.record_success("incident-1", "investigation", {}, {})
    recorder.record_success("incident-2", "investigation", {}, {})
    recorder.record_success("incident-1", "threat_reasoning", {}, {})
    traces = recorder.list_for_agent("investigation")
    assert len(traces) == 2


def test_all_traces_preserves_call_order():
    recorder = AgentTraceRecorder()
    recorder.record_success("incident-1", "investigation", {}, {})
    recorder.record_failure("incident-1", "threat_reasoning", {}, "boom")
    traces = recorder.all_traces()
    assert [t.agent_name for t in traces] == ["investigation", "threat_reasoning"]
