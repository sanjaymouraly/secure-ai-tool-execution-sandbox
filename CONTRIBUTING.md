# Contributing

Thank you for considering a contribution. This project is a security
tool, so contributions are reviewed with that in mind.

## Ground rules

1. **Never weaken a test to make it pass.** A failing security assertion is
   a finding, not an obstacle. If a control has to change, the change must be
   argued in the pull request and the documentation must be updated with it.
2. **Never widen a default.** New capabilities ship disabled. A feature that
   needs an opt-in is opt-in.
3. **The policy engine is the security boundary.** Changes to
   `backend/app/policy/`, `backend/app/core/guards.py`,
   `backend/app/core/paths.py` or `backend/app/core/commands.py` need a
   security review and a corresponding test.
4. **Document the limitation.** If a change introduces a new limitation, add
   it to `docs/limitations.md` in the same pull request.

## Development setup

### Linux

```bash
./scripts/setup-linux.sh
source .venv/bin/activate
```

### Windows

```powershell
.\scripts\setup-windows.ps1
.\.venv\Scripts\Activate.ps1
```

### Manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
(cd frontend && npm install)
cp .env.example .env
docker build -t secure-ai-sandbox-runner:latest docker/sandbox
(cd backend && alembic upgrade head)
```

## Running the checks

```bash
./scripts/verify.sh
```

This runs, in order: Ruff lint, Ruff format check, mypy, Bandit,
detect-secrets, pip-audit, `npm audit`, the frontend type check, the backend
test suite and a `docker compose config` validation.

Individual tools:

```bash
ruff check backend/app backend/tests
ruff format backend/app backend/tests
mypy backend/app --ignore-missing-imports
bandit -r backend/app
pytest backend/tests -q
pytest backend/tests -m docker -q      # real container isolation
pytest backend/tests -m e2e -q         # browser tests (needs a running stack)
(cd frontend && npm run typecheck && npm run build)
```

## Test expectations for a change

| Change | Test that must be added or updated |
| ------ | ---------------------------------- |
| A new tool | Tool manifest test, policy rule, schema validation test, broker test |
| A new policy effect or constraint | Policy engine unit test **and** an attack-lab scenario |
| A new path handling rule | A path traversal / symlink test in `tests/test_paths.py` |
| A new command | Allowlist test in `tests/test_commands.py` |
| A new sandbox flag | Isolation test in `tests/test_sandbox.py` |
| A new API endpoint | Route test in `tests/test_api.py` plus an entry in `docs/api-reference.md` |
| A new provider | Provider adapter test in `tests/test_providers.py` |

## Commit and pull request style

* One logical change per pull request.
* Describe **why** in the pull request body, not only **what**.
* Reference the issue or the threat model section that motivated the change.
* Update the documentation and the changelog.
* Screenshots of the dashboard belong in `docs/images/` and must be produced
  by `scripts/capture_screenshots.py` against a running application.

## Adding an attack-lab scenario

1. Add the scenario to `backend/attack_lab/scenarios.yaml`.
2. Add the fixture it needs under `sandbox_workspace/`.
3. Run `pytest backend/tests/test_attack_lab.py -q` — the whole catalogue must
   pass.
4. Document the scenario in `docs/attack-lab.md`.

A scenario that fails is a real finding. Do not weaken the expectation to make
it pass; fix the control instead.
