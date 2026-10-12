# docs

Project documentation: architecture, research methodology, threat model, agent
architecture, risk model, blockchain architecture, simulator, datasets, API,
experiments, deployment, security, limitations, future work. Evolves with
implementation — a claim here is only written once the component it describes is
actually built and tested.

- `architecture.md` — the Phase 0 specification, a frozen, versioned copy of
  the live external artifact (see its own header). Describes what was
  planned before Phases 1–14 were built, not what they ended up building.
- `security-checklist.md` — the Phase 12 security hardening pass, verified
  item by item against the real code.
- `phase15-verification.md` — the Phase 15 pass: every checkable claim in
  `architecture.md` re-verified against the real, current code, with every
  place reality diverged from the Phase 0 plan named explicitly rather than
  left for `architecture.md` to silently misstate. Read this one first if
  you want to know what's actually true today versus what was originally
  planned.
