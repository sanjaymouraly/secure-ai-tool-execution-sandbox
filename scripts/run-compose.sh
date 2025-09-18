#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Start the complete stack with Docker Compose.
#
#   ./scripts/run-compose.sh
#
# The dashboard is published on http://127.0.0.1:8080 and the API on
# http://127.0.0.1:8000.  Neither is exposed to the network.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f .env ]]; then
    echo "==> .env is missing. Run ./scripts/setup-linux.sh first." >&2
    exit 1
fi

# The Compose file needs the secrets as variables.
set -a
# shellcheck disable=SC1091
source .env
set +a

echo "==> Building the sandbox image"
docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .

echo "==> Starting the stack"
docker compose up --build -d

echo "==> Waiting for the backend to become healthy"
for _ in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
        echo "==> The backend is healthy"
        break
    fi
    sleep 2
done

cat <<'EOF'

The stack is running:

  Dashboard  http://127.0.0.1:8080
  API        http://127.0.0.1:8000/api/docs
  Health     http://127.0.0.1:8000/health

Sign in with the bootstrap administrator from .env.

  Logs       docker compose logs -f backend
  Stop       docker compose down

EOF
