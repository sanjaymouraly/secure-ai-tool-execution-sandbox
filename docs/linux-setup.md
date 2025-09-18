# Linux setup

Ubuntu, Debian and other mainstream distributions. The script is
idempotent — run it again after pulling new code.

## Requirements

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Python | 3.12 or newer | `python3 --version` |
| Docker Engine | 24 or newer | The sandbox backend needs a working daemon |
| Docker Compose | v2 | Optional, for the containerised stack |
| Node.js | 20 or newer | Only needed for the dashboard |
| `python3-venv` | — | `sudo apt-get install python3-venv` |

## One command

```bash
git clone https://github.com/<your-org>/secure-ai-tool-execution-sandbox.git
cd secure-ai-tool-execution-sandbox
./scripts/setup-linux.sh
```

The script installs the Python dependencies, installs the frontend
dependencies, creates `.env` with freshly generated secrets, builds the
hardened sandbox image and initialises the database.

## Manual setup

```bash
# 1. System packages
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip nodejs npm docker.io docker-compose-v2

# 2. Docker (rootless is recommended but optional)
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker                      # log out and back in afterwards

# 3. Python environment
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements-dev.txt

# 4. Frontend
(cd frontend && npm install)

# 5. Configuration
cp .env.example .env
python - <<'PY'
import secrets
from cryptography.fernet import Fernet
print("SAXIS_SECRET_KEY=" + secrets.token_urlsafe(48))
print("SAXIS_PROVIDER_SECRET_KEY=" + Fernet.generate_key().decode())
PY
# paste the two lines into .env

# 6. The hardened sandbox image
docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .

# 7. Database
(cd backend && alembic upgrade head)
```

## Running

### Development (two terminals)

```bash
# Terminal 1 - backend
source .venv/bin/activate
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
# Terminal 2 - dashboard
cd frontend
npm run dev
```

Open <http://127.0.0.1:5173> and sign in with the bootstrap administrator
from `.env` (`SAXIS_BOOTSTRAP_ADMIN_USERNAME` / `SAXIS_BOOTSTRAP_ADMIN_PASSWORD`).

### With Docker Compose

```bash
./scripts/run-compose.sh
```

The dashboard is published on <http://127.0.0.1:8080> and the API on
<http://127.0.0.1:8000>. Both bind to the loopback interface only.

```bash
docker compose logs -f backend   # logs
docker compose down              # stop
```

### With a local model (Ollama)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
ollama serve &
```

Set these in `.env`:

```dotenv
SAXIS_DEFAULT_PROVIDER=ollama
SAXIS_PROVIDER_BASE_URL=http://localhost:11434/v1
SAXIS_PROVIDER_MODEL=qwen2.5:1.5b
```

`gemma2:2b` also works, but Ollama does not support native tool calls for
that model, so the adapter falls back to prompt-based tool calling.

If Ollama runs in a container, use `http://host.docker.internal:11434/v1`.

## Running the tests

```bash
source .venv/bin/activate
cd backend

pytest -q                       # the whole suite
pytest -q -m docker             # only the real container isolation tests
pytest -q -m "not docker"       # skip them (no Docker daemon needed)
pytest -q tests/test_attack_lab.py    # the prompt-injection laboratory
```

The browser tests need a running stack:

```bash
pytest -q -m e2e
```

## Troubleshooting

### "The Docker daemon is not reachable"

```bash
sudo systemctl status docker
sudo usermod -aG docker "$USER"   # then log out and back in
docker info                       # must not print an error
```

The system **refuses to fall back to unsandboxed execution**. Fix Docker
rather than switching to the simulation backend.

### "permission denied while trying to connect to the Docker daemon"

Your user is not in the `docker` group, or the socket has the wrong
permissions.

```bash
ls -l /var/run/docker.sock
sudo usermod -aG docker "$USER"
newgrp docker
```

### "address already in use"

```bash
sudo lsof -i :8000
sudo lsof -i :5173
# or use a different port
uvicorn app.main:app --port 8010
```

### "no matching manifest for secure-ai-sandbox-runner"

```bash
docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .
```

### "the model is not found" / provider errors

```bash
ollama list                       # is the model pulled?
curl http://localhost:11434/api/tags
```

Set `SAXIS_DEFAULT_PROVIDER=simulation` to run the deterministic offline
planner while you debug the provider configuration.

### "SAXIS_SECRET_KEY must be set explicitly in production"

Generate one and put it in `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### The audit chain reports a broken sequence

Something wrote to the audit table directly, or a record was deleted. Check
`GET /api/v1/audit/verify` for the exact sequence and reason, then restore
the database from a backup. This is the chain doing its job.

### The dashboard shows "Sandbox unavailable"

The backend cannot reach Docker. `GET /ready` reports the detail. The
sandbox image must also exist:

```bash
docker images secure-ai-sandbox-runner
```
