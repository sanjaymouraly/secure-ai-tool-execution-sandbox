# Windows setup

The steps below work on Windows 10 (build 19045 or newer) and Windows 11.

## Requirements

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Python | 3.12 or newer | Install from <https://www.python.org/downloads/windows/> and tick *Add python.exe to PATH* |
| Docker Desktop | 4.25 or newer | **Linux containers** mode is mandatory |
| Node.js | 20 or newer | <https://nodejs.org/> — only needed for the dashboard |
| PowerShell | 5.1 or newer | Windows PowerShell ships with Windows; PowerShell 7 also works |

> **Docker Desktop must use Linux containers.** Right-click the tray icon →
> *Switch to Linux containers*. The sandbox relies on Linux namespaces,
> capabilities and seccomp, none of which exist in the Windows container
> format.

## One command (PowerShell)

```powershell
git clone https://github.com/<your-org>/secure-ai-tool-execution-sandbox.git
cd secure-ai-tool-execution-sandbox
.\scripts\setup-windows.ps1
```

If the execution policy blocks the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup-windows.ps1
```

## Manual setup

```powershell
# 1. Python environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements-dev.txt

# 2. Frontend
cd frontend
npm install
cd ..

# 3. Configuration
Copy-Item .env.example .env
python -c "import secrets; print('SAXIS_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('SAXIS_PROVIDER_SECRET_KEY=' + Fernet.generate_key().decode())"
# paste both lines into .env

# 4. The hardened sandbox image
docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .

# 5. Database
cd backend
python -m alembic upgrade head
cd ..
```

## Running

### Development (two PowerShell windows)

```powershell
# Window 1 - backend
.\.venv\Scripts\Activate.ps1
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```powershell
# Window 2 - dashboard
cd frontend
npm run dev
```

Open <http://127.0.0.1:5173> and sign in with the bootstrap administrator
from `.env`.

### With Docker Compose

```powershell
Copy-Item .env.example .env
# fill in SAXIS_SECRET_KEY and SAXIS_BOOTSTRAP_ADMIN_PASSWORD
docker compose up --build -d
docker compose logs -f backend
```

The dashboard is published on <http://127.0.0.1:8080>.

### With a local model (Ollama for Windows)

Download the installer from <https://ollama.com/download/OllamaSetup.exe>,
then:

```powershell
ollama pull qwen2.5:1.5b
ollama serve
```

Set these in `.env`:

```dotenv
SAXIS_DEFAULT_PROVIDER=ollama
SAXIS_PROVIDER_BASE_URL=http://localhost:11434/v1
SAXIS_PROVIDER_MODEL=qwen2.5:1.5b
```

Ollama on Windows runs in a WSL2 distribution, so `localhost:11434` usually
works from both Windows and WSL.

## Running the tests

```powershell
.\.venv\Scripts\Activate.ps1
cd backend
pytest -q
```

The Docker isolation tests run against Docker Desktop on Windows, but the
Windows CI job only runs the platform-independent subset. Expect the
`docker` marked tests to be slow on Windows because the file system is
slower.

## Troubleshooting

### "Docker Desktop is required"

Install Docker Desktop and start it. The system **refuses to fall back to
unsandboxed execution** — this is deliberate. Fix Docker instead.

### "cannot switch to Linux containers"

The Windows container feature is not installed, or the Hyper-V / WSL2
backend is missing. In Docker Desktop: *Settings → General → Use the WSL 2
based engine*. Install WSL2 with `wsl --install`.

### "exec format error" when the sandbox container starts

Docker is in Windows container mode. Switch to Linux containers.

### "address already in use"

```powershell
Get-NetTCPConnection -LocalPort 8000
Get-NetTCPConnection -LocalPort 5173
```

### "cannot open volume ... permission denied" with a bind mount

The Docker Desktop file sharing settings must include the drive that holds
the repository (*Settings → Resources → File sharing*).

### The `local-simulated` backend does not work

`preexec_fn` is POSIX-only. On Windows use the Docker backend.

### Long paths fail

Enable long path support:

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### PowerShell refuses to run the activation script

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
