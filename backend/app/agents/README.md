# agents

L4 of the architecture. The five agents — Investigation, Threat Reasoning, Healthcare
Context, Response Planning, Recovery Verification — each with its own input/output
schema, a read-only tool allowlist, and a persisted trace record per call. None of
these agents hold an execute capability; only the Response Orchestrator (L7) does.

Status: not started. Phase 4 work.
