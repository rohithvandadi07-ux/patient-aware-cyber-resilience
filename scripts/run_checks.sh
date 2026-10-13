#!/usr/bin/env bash
# Runs the backend test suite + lint, and the frontend test suite + lint +
# build, in one command -- the same checks docs/reproducibility.md §3 lists
# individually. Dependency/vulnerability scans (pip-audit, npm audit) run
# too, but never fail the script (their results are point-in-time, not
# pass/fail gates for local dev).
#
# Usage: ./scripts/run_checks.sh [--skip-frontend] [--skip-e2e]
#
# Exits non-zero on the first failing *required* step. The Playwright E2E
# suite is opt-in (--include-e2e) since it needs `playwright install
# chromium` first and starts real backend/frontend processes -- see
# tests/README.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_FRONTEND=0
INCLUDE_E2E=0

for arg in "$@"; do
  case "$arg" in
    --skip-frontend) SKIP_FRONTEND=1 ;;
    --include-e2e) INCLUDE_E2E=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

echo "== Backend: ruff check =="
cd "$REPO_ROOT/backend"
if [ ! -d .venv ]; then
  echo "backend/.venv not found -- run: cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt" >&2
  exit 1
fi
source .venv/bin/activate
ruff check app

echo "== Backend: pytest =="
pytest -q

echo "== Backend: pip-audit (advisory, never fails this script) =="
pip-audit || echo "pip-audit reported findings or could not run -- review above, not treated as fatal here."

if [ "$SKIP_FRONTEND" -eq 0 ]; then
  echo "== Frontend: lint =="
  cd "$REPO_ROOT/frontend"
  if [ ! -d node_modules ]; then
    echo "frontend/node_modules not found -- run: cd frontend && npm install" >&2
    exit 1
  fi
  npm run lint

  echo "== Frontend: test =="
  npm run test

  echo "== Frontend: build =="
  npm run build

  echo "== Frontend: npm audit (advisory, never fails this script) =="
  npm audit || echo "npm audit reported findings or could not run -- review above, not treated as fatal here."
fi

if [ "$INCLUDE_E2E" -eq 1 ]; then
  echo "== Playwright E2E (Scenario A/B through the real UI) =="
  cd "$REPO_ROOT/backend"
  source .venv/bin/activate
  pytest -c "$REPO_ROOT/tests/pytest.ini" "$REPO_ROOT/tests/e2e"
fi

echo "== All checks completed =="
