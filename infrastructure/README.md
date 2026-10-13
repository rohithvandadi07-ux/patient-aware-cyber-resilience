# infrastructure

Architecture spec Section 6 planned this directory to hold `docker-compose.yml`
and the Dockerfiles. That's not where they actually ended up, found and
corrected during Phase 15's documentation pass rather than left stale: Phase 1
put `docker-compose.yml` at the repo root (so `docker compose up` works from
the directory a developer actually clones into, with no `-f` flag needed), and
Phase 14 put `backend/Dockerfile` and `frontend/Dockerfile` beside the code
each one builds, not in a shared top-level folder — the more common layout
when a repo has exactly one Dockerfile per service. This directory is kept
(with this note) rather than deleted, since Section 6 names it explicitly;
nothing here should be assumed to exist on disk without checking.

No Kubernetes or other orchestration at this stage — the brief explicitly
warns against premature over-engineering. Fabric's network is deliberately
*not* part of `docker-compose.yml` at all — see the root `README.md`'s
"Docker" section and `blockchain/network/README.md` for why (this project's
development sandbox blocks every container registry it tried, the same
constraint that already pushed Fabric to native binaries in Phase 8).

**No Infrastructure-as-Code (Terraform, Ansible, Kubernetes manifests, or
similar) exists here, and none is planned.** Stated plainly rather than
left implied by an empty directory: this is a single-researcher, local-dev
prototype with one deployment target (a developer's own machine, via
`docker compose up` or native processes — see `docs/deployment.md`), not a
multi-environment or cloud deployment with infrastructure worth codifying.
Introducing IaC now would be provisioning for environments and scale this
project has never needed or been asked to support. If a real multi-
environment deployment is ever required, that is the point to add real
Terraform/Ansible/k8s configuration here — not before.
