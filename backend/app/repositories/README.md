# repositories

Database access layer, one repository per aggregate (devices, incidents, agent
traces, approvals, blockchain outbox, etc.). Services call repositories; routers
never touch the database directly.

Status: not started. Built incrementally alongside each layer that needs persistence,
starting in Phase 2.
