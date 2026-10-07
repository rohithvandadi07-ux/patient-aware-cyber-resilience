# schemas

Pydantic models that define the structured contracts between every layer of the
system — detection output, agent inputs/outputs, risk scores, proposed and executed
responses, recovery results. These are the interfaces described in the architecture
specification (Section 11 and others); later phases build against them rather than
inventing ad hoc dicts.

Status: scaffolded (Phase 1) — typed but not yet wired to any business logic.
