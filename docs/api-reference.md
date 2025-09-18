# API reference

Base URL: `http://127.0.0.1:8000`
Versioned prefix: `/api/v1`
Interactive documentation: `/api/docs` (OpenAPI, generated from the code)

## Authentication

Two mechanisms are supported.

**Session cookie (recommended for the dashboard).** `POST /api/v1/auth/login`
returns a JWT and sets two cookies:

| Cookie | HttpOnly | Purpose |
| ------ | -------- | ------- |
| `sax_session` | yes | The signed session token |
| `sax_csrf` | no | The CSRF token, echoed back in `X-CSRF-Token` |

Every state-changing request made with the cookie must include the
`X-CSRF-Token` header. A missing or wrong token returns `403`.

**Bearer token.** The `access_token` from the login response can be sent as
`Authorization: Bearer <token>`; the CSRF header is then not required.

The credential is never stored in `localStorage` by the dashboard.

## Roles

| Role | May |
| ---- | --- |
| `admin` | Everything, including editing the policy and exporting the audit trail |
| `approver` | Decide approval requests; run tools |
| `analyst` | Run tools, use the agent, run the attack laboratory |
| `viewer` | Read only |

---

## System

### `GET /health`

Liveness probe. Always `200` while the process runs.

```json
{
  "status": "healthy",
  "timestamp": "2026-10-19T16:36:11.143434+00:00",
  "service": "Secure AI Tool Execution & Permission Sandbox",
  "version": "1.0.0",
  "uptime_seconds": 6.83
}
```

### `GET /ready`

Readiness probe. Returns `503` when the database is unreachable.

```json
{
  "status": "ready",
  "database": "ok",
  "sandbox": {
    "name": "docker",
    "available": true,
    "isolated": true,
    "detail": "Docker Engine with hardened container flags",
    "image": "secure-ai-sandbox-runner:latest",
    "rootless": false,
    "apparmor": true,
    "seccomp": true,
    "user_namespaces": false,
    "warnings": ["The Docker daemon is not running rootless; ..."],
    "version": "29.8.0-1"
  },
  "policy_version": "2.0.0",
  "timestamp": "2026-10-19T16:36:12.000000+00:00"
}
```

### `GET /system/info`

Static deployment information. Requires authentication.

### `GET /overview`

Aggregated metrics for the dashboard. Requires authentication.

```json
{
  "generated_at": "2026-10-19T16:36:33.537966+00:00",
  "executions": {
    "total": 69, "completed": 42, "denied": 18, "failed": 0,
    "awaiting_approval": 9, "timed_out": 0, "last_24h": 69,
    "by_tool": {"list_files": 26, "read_file": 18},
    "by_outcome": {"completed": 42, "denied": 18}
  },
  "audit": {"total_events": 70},
  "usage": {
    "total_cost_usd": 0.0, "total_tokens": 3341,
    "session_budget_usd": 1.0, "daily_budget_usd": 10.0
  },
  "policy": {"version": "2.0.0", "revision": 1, "rules": 12},
  "provider": {"default": "ollama", "model": "qwen2.5:1.5b"},
  "recent_executions": [ /* … */ ]
}
```

### `GET /metrics`

Simple JSON metrics.

---

## Authentication — `/api/v1/auth`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `POST` | `/login` | public | Sign in; returns a token and sets the session cookies |
| `POST` | `/logout` | public | Clear the session cookies |
| `GET` | `/me` | any | The current user and its permissions |
| `POST` | `/change-password` | any | Change the own password (12 characters minimum) |
| `POST` | `/register` | public | Register a user (disabled unless `SAXIS_ALLOW_REGISTRATION=true`) |

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin-change-me"}'
```

---

## Tools — `/api/v1/tools`

### `GET /api/v1/tools`

The tool manifest: name, description, risk, category and the JSON schema.

### `POST /api/v1/tools/{tool_name}/invoke`

Invoke a tool through the full security pipeline. The body is:

```json
{
  "arguments": { "path": "documents/quarterly-report.md" },
  "session_id": null,
  "agent_id": "default",
  "project_id": "",
  "approval_id": null
}
```

The response:

```json
{
  "execution_id": "39b249d6d29f4cb198ad5525b0aa0ce7",
  "trace_id": "tr-4552cd7d308640eda5e6",
  "tool_name": "read_file",
  "status": "completed",
  "decision": {
    "allowed": true,
    "effect": "allow",
    "reason": "Reading approved text documents is permitted for analysis workflows.",
    "rule_id": "allow-read-approved-documents",
    "rule_description": "Allow reading approved text documents from the workspace.",
    "policy_version": "2.0.0",
    "policy_revision": 1,
    "source": "policy",
    "explanation": [
      "All hard guards passed.",
      "Rule 'allow-read-approved-documents' matched tool='read_file' priority=490.",
      "Matched constraints: allowed_extensions=[...]"
    ],
    "matched_constraints": ["allowed_extensions=[...]"],
    "requires_approval": false
  },
  "approval_required": false,
  "approval_id": null,
  "output": "{\"path\": \"documents/quarterly-report.md\", ...}",
  "error": null,
  "exit_code": 0,
  "duration_ms": 2,
  "sandbox_id": "",
  "sandbox_backend": "",
  "isolated": false,
  "metadata": {}
}
```

`status` is one of `completed`, `denied`, `failed`, `awaiting_approval`,
`timeout`.

---

## Workspace — `/api/v1/workspace`

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/workspace?path=documents&recursive=false` | List a directory |
| `GET` | `/workspace/file?path=documents/report.md` | Read a file |

Both use the same path resolver and the same policy engine as the agent
tools, so the view matches exactly what the agent can reach. A denied
directory returns `allowed: false` together with the decision.

---

## Sessions and the agent — `/api/v1/sessions`

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/sessions` | List the sessions of the user |
| `POST` | `/sessions` | Create a session |
| `GET` | `/sessions/{id}` | A session with its messages and executions |
| `POST` | `/sessions/{id}/run` | Run the agent loop |
| `POST` | `/sessions/{id}/cancel` | Request cancellation |
| `DELETE` | `/sessions/{id}` | Delete a session |
| `GET` | `/sessions/{id}/export` | Export the full trace |

```bash
curl -X POST http://127.0.0.1:8000/api/v1/sessions \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Demo"}'

curl -X POST http://127.0.0.1:8000/api/v1/sessions/$SESSION/run \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"message":"Read documents/quarterly-report.md and summarise it."}'
```

The run response contains the steps, the executions, the token usage, the
estimated cost and the final answer.

---

## Approvals — `/api/v1/approvals`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `GET` | `/approvals?status=pending` | any | List the approval requests |
| `GET` | `/approvals/pending` | any | Only the pending requests |
| `POST` | `/approvals/{id}/decision` | approver | `allow_once`, `allow_for_session` or `deny` |
| `POST` | `/approvals/grants/revoke` | approver | Revoke the session grants |

An approver may not decide an approval they requested themselves.

---

## Policy — `/api/v1/policies`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `GET` | `/policies/current` | any | The active document and the evaluation order |
| `POST` | `/policies/current` | admin | Replace the document (validated, versioned, audited) |
| `POST` | `/policies/validate` | admin | Validate a document without installing it |
| `POST` | `/policies/reload` | admin | Re-read the document from disk |
| `GET` | `/policies/history` | admin | The stored versions |
| `GET` | `/policies/export` | admin | Export the document as YAML and JSON |

---

## Executions — `/api/v1/executions`

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/executions?status=&tool_name=&session_id=&limit=` | List the executions |
| `GET` | `/executions/{id}` | One execution with the full output |

---

## Audit — `/api/v1/audit`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `GET` | `/audit/events` | any | Search the trail |
| `GET` | `/audit/verify` | any | Verify the integrity chain |
| `GET` | `/audit/export?fmt=json\|csv` | admin | Export the trail |
| `DELETE` | `/audit/retention` | admin | Apply the retention window |

Filters: `action`, `tool_name`, `outcome`, `actor_id`, `session_id`,
`trace_id`, `since_hours`, `limit`, `offset`.

The verification response:

```json
{
  "valid": true,
  "records": 70,
  "broken": [],
  "checked_at": "2026-10-19T16:40:07.000000+00:00"
}
```

---

## Providers — `/api/v1/providers`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `GET` | `/providers/types` | any | The supported provider types and the price table |
| `GET` | `/providers` | any | The configured profiles |
| `POST` | `/providers` | admin | Create a profile |
| `PUT` | `/providers/{id}` | admin | Update a profile |
| `DELETE` | `/providers/{id}` | admin | Delete a profile |
| `POST` | `/providers/{id}/test` | any | Test the connection |
| `GET` | `/providers/models` | any | Discover the models of the endpoint |
| `POST` | `/providers/estimate` | any | Estimate the cost of a call |

A stored API key is encrypted with `SAXIS_PROVIDER_SECRET_KEY`; the API
never returns it, only a short hint.

---

## Attack laboratory — `/api/v1/attack-lab`

| Method | Path | Role | Description |
| ------ | ---- | ---- | ----------- |
| `GET` | `/attack-lab/scenarios` | any | The scenario catalogue |
| `GET` | `/attack-lab/runs` | any | The recorded runs and the statistics |
| `POST` | `/attack-lab/run/{scenario_id}` | any | Run one scenario |
| `POST` | `/attack-lab/run-all` | any | Run the whole catalogue |

The statistics:

```json
{
  "total_runs": 34,
  "malicious_total": 24,
  "malicious_blocked": 24,
  "attack_success_rate": 0.0,
  "deny_count": 17,
  "approval_count": 6,
  "budget_blocked": 1,
  "benign_total": 10,
  "benign_allowed": 10,
  "false_positive_count": 0,
  "false_positive_rate": 0.0,
  "by_category": { "instruction-override": {"total": 2, "blocked": 2, "passed": 2} }
}
```

---

## Error format

```json
{ "detail": "A human approval is required before this action can run." }
```

| Status | Meaning |
| ------ | ------- |
| `400` | The request was malformed or a path was not resolvable |
| `401` | Authentication is required or the token is invalid |
| `403` | The role or the CSRF check refused the request |
| `404` | The object does not exist |
| `409` | A conflict, for example deciding an approval twice |
| `422` | The request body failed validation |
| `429` | The rate limit was exceeded (`Retry-After` is set) |
| `500` | An unexpected error. The details are logged, never returned |
| `503` | A dependency is unavailable, for example the Docker daemon |
