# Testing

The test-suite exercises the **real** policy engine, the **real** broker and
— where a Docker daemon is available — the **real** container sandbox. Only
the external LLM provider is mocked, and it is mocked behind the provider
interface so that everything downstream stays genuine.

## Quick start

```bash
source .venv/bin/activate
cd backend
pytest -q
```

## Test inventory

| File | What it covers |
| ---- | -------------- |
| `tests/test_paths.py` | Traversal, absolute escape, percent encoding, NUL bytes, symlink escape, hard links, atomic writes, `O_NOFOLLOW` |
| `tests/test_commands.py` | Shell metacharacters, allowlisting, absolute program paths, path separators, argument smuggling, flag denial, argv patterns |
| `tests/test_policy_engine.py` | The default policy, guard precedence, protected paths, symlink laundering, network and destructive command denial, schema validation, rule ordering, argument signatures, session grants |
| `tests/test_broker.py` | The full pipeline: allowed reads, denials, approvals, approval scope widening, session grants, revocation, audit records, artifact round trips, the protected file staying unchanged |
| `tests/test_api.py` | Authentication, roles, CSRF, the tool API, the policy editor, approvals, the audit trail, the overview, session lifecycle, security headers |
| `tests/test_providers.py` | Tool-call parsing, error classification (401, 429, timeout, malformed JSON), missing credentials, the Anthropic adapter, the deterministic simulation provider, cost estimation, budget enforcement |
| `tests/test_agent.py` | The agent loop, message persistence, the step limit, cancellation, denied actions reported to the model, provider failure, usage and cost recording |
| `tests/test_attack_lab.py` | The complete prompt-injection catalogue, the protected fixture integrity, the statistics, and that the documentation covers every scenario |
| `tests/test_audit.py` | The integrity chain, tamper detection, sequence gaps, redaction, export, retention |
| `tests/test_sandbox.py` | Real container isolation: non-root, read-only root filesystem, no host filesystem, no Docker socket, network denial, DNS failure, timeout, memory and PID limits, output truncation, clean-up, no secret in the environment |
| `tests/test_concurrency.py` | Concurrent executions, mixed allowed/denied operations, session independence, no silent fallback when the sandbox breaks, job workspace clean-up |
| `tests/test_e2e.py` | Browser tests against the running application |

## Markers

| Marker | Meaning |
| ------ | ------- |
| `docker` | Requires a running Docker daemon. **Skipped** when there is none — never faked. |
| `e2e` | Requires a running frontend and backend. Skipped when unreachable. |
| `slow` | Long running. |

```bash
pytest -q -m docker              # only the real isolation tests
pytest -q -m "not docker"        # everything that does not need Docker
pytest -q -m e2e                 # the browser tests
```

The test-suite picks the backend automatically:

* `SAXIS_TEST_SANDBOX_BACKEND=docker` — use the real container sandbox.
* `SAXIS_TEST_SANDBOX_BACKEND=local-simulated` — use the non-isolating
  simulation backend (only for machines without Docker).
* Unset — Docker when a daemon is reachable, otherwise the simulation.

## Coverage

```bash
pytest --cov=app --cov-report=term-missing --cov-report=html
```

The HTML report is written to `htmlcov/`.

## The browser tests

```bash
# terminal 1
cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8000

# terminal 2
cd frontend && npm run dev

# terminal 3
cd backend && pytest -q -m e2e
```

Configuration through the environment:

| Variable | Default |
| -------- | ------- |
| `SAXIS_E2E_FRONTEND_URL` | `http://127.0.0.1:5173` |
| `SAXIS_E2E_BACKEND_URL` | `http://127.0.0.1:8000` |
| `SAXIS_E2E_USERNAME` | `admin` |
| `SAXIS_E2E_PASSWORD` | `admin-change-me` |

## The quality gates

```bash
./scripts/verify.sh
```

| Gate | Tool | What it catches |
| ---- | ---- | --------------- |
| Lint | `ruff check` | Style and bug patterns (`B`, `S`, `SIM`, `UP`) |
| Format | `ruff format --check` | Formatting drift |
| Types | `mypy` | Incorrect type usage in the application code |
| Security lint | `bandit` | Known insecure patterns |
| Secret scan | `detect-secrets` | Credentials committed to the repository |
| Dependency audit | `pip-audit` | Known vulnerable Python packages |
| Dependency audit | `npm audit` | Known vulnerable npm packages |
| Frontend types | `tsc --noEmit` | Type errors in the dashboard |
| Tests | `pytest` | Behavioural regressions |
| Container config | `docker compose config` | Invalid compose files |

## Security test philosophy

* A test that exercises an allow/deny path must call the **real** policy
  engine. There are no mocked allow/deny results in this repository.
* The only mocks are of the LLM provider, which is a paid external service.
  The mock sits behind `Provider.chat`, so the schema validation, the policy
  evaluation, the approval flow, the sandbox and the audit trail are all
  real.
* The sandbox tests assert on the *observable* effect — a socket that cannot
  be created, a file that cannot be written, a process that is killed — not
  on a configuration flag.
* The attack laboratory compares the expected outcome with the observed one
  and fails when they differ. A failing scenario is a finding.
* The protected fixture `sandbox_workspace/protected/secret.txt` is hashed
  before and after every scenario, and the test fails if the hash changed.

## Writing a new test

```python
async def test_a_denied_action_is_recorded(container, db, analyst_user):
    result = await container.broker.execute(
        db,
        tool_name="read_file",
        arguments={"path": "protected/secret.txt"},
        user=analyst_user,
    )
    assert result.status == "denied"
    assert result.decision.rule_id == "deny-protected-workspace-paths"
```

Notes:

* `asyncio_mode = "auto"` is configured, so `async def test_…` works without a
  decorator.
* Use the `container` fixture for the real stack, `lab_container` for the
  repository workspace fixtures, and `db` for a clean database.
* Never weaken an assertion to make a test pass. Fix the control.

## Regression policy

Every bug fix must come with a test that fails before the fix and passes
after it. The test name should describe the security property, not the
implementation detail, for example:

* `test_approval_scope_cannot_be_widened`
* `test_symlink_laundering_is_denied`
* `test_no_container_is_left_behind`
