#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run the complete verification suite: linting, formatting, type checking,
# dependency auditing, secret scanning and the test suite.
#
#   ./scripts/verify.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENV="${VENV:-$REPO_ROOT/.venv}"
PYTHON="$VENV/bin/python"
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3 || command -v python)"
fi

FAILED=0
step() {
    echo ""
    echo "==================================================================="
    echo "== $1"
    echo "==================================================================="
}
run() {
    if "$@"; then
        echo "-- PASSED: $*"
    else
        echo "-- FAILED: $*"
        FAILED=1
    fi
}

step "Ruff (lint)"
run "$PYTHON" -m ruff check backend/app backend/tests scripts

step "Ruff (format check)"
run "$PYTHON" -m ruff format --check backend/app backend/tests scripts

step "Mypy (type check)"
run "$PYTHON" -m mypy backend/app --ignore-missing-imports --no-error-summary

step "Bandit (security lint)"
run "$PYTHON" -m bandit -r backend/app -q

step "detect-secrets (secret scan)"
run "$PYTHON" -m detect_secrets scan --baseline .secrets.baseline --exclude-files '(\.git|node_modules|dist|package-lock\.json|docs/images)' backend frontend scripts docker .env.example

step "pip-audit (dependency audit)"
if "$PYTHON" -m pip_audit --requirement backend/requirements.txt --strict; then
    echo "-- PASSED: pip-audit"
else
    # Some hosts cannot create the isolated environment pip-audit needs.
    # Fall back to auditing the current environment.
    echo "-- retrying against the current environment"
    if "$PYTHON" -m pip_audit --local; then
        echo "-- PASSED: pip-audit --local"
    else
        echo "-- FAILED: pip-audit"
        FAILED=1
    fi
fi

step "npm audit (frontend dependencies)"
if command -v npm >/dev/null 2>&1; then
    (cd frontend && npm audit --audit-level=high) || FAILED=1
else
    echo "-- SKIPPED: npm is not installed"
fi

step "Frontend type check"
if command -v npm >/dev/null 2>&1; then
    (cd frontend && npm run typecheck) || FAILED=1
else
    echo "-- SKIPPED: npm is not installed"
fi

step "Backend test suite"
run "$PYTHON" -m pytest backend/tests -q

step "Container configuration check"
if command -v docker >/dev/null 2>&1; then
    docker compose config --quiet && echo "-- PASSED: docker compose config"
else
    echo "-- SKIPPED: docker is not installed"
fi

echo ""
if [[ "$FAILED" -eq 0 ]]; then
    echo "All verification steps passed."
else
    echo "One or more verification steps FAILED." >&2
fi
exit "$FAILED"
