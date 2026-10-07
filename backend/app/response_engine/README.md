# response_engine

L7 of the architecture. The Response Orchestrator — the only service in the system
that executes a response action, and only the action the Policy Engine has cleared
(autonomously or via human approval). Calls the simulator's command interface;
never touches real infrastructure.

Status: not started. Phase 6 work.
