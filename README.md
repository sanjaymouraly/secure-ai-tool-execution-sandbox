# Secure AI Tool Execution & Permission Sandbox

Runs AI tool calls inside a permissioned sandbox with policy enforcement and execution limits.

## Features

- Deny-by-default policy engine with a strict, versioned YAML/JSON schema.
- Rules are evaluated in a stable order (descending priority, then ascending id); the first matching rule decides.
- Hard guards — code-enforced invariants that run *before* the policy and can never be relaxed by a policy change: path traversal, symlink escape, shell metacharacters, network access, oversized arguments, privileged standard library imports.
- Every decision returns a human-readable explanation, the matched rule and the matched constraints.
- Scoping by user, role, agent, project and session; file scopes; command allowlists; tool-specific argument restrictions; expiry and revocation.
- Allow once, Allow for session and Deny.
- An approval is bound to a SHA-256 signature over the canonical tool name and arguments, and it is re-validated immediately before execution. *An approval can never authorise a broader action than the one a human reviewed.*

## Stack

Python, Node.js, FastAPI, Uvicorn, Pydantic, SQLAlchemy, HTTPX, PyYAML, React, TypeScript

## Clone

```bash
git clone https://github.com/sanjaymouraly/secure-ai-tool-execution-sandbox.git
cd secure-ai-tool-execution-sandbox
```

## Setup

```bash
# The project ships a Docker Compose setup.
docker compose up --build
```

See `docs/` or the compose file for environment variables and ports.

## Run

```bash
docker compose up --build
```

## Tests

```bash
pytest -q
```

## Notes

- Sample data, when included, is synthetic.

## License

MIT © 2025 [Sanjay Mouraly](https://github.com/sanjaymouraly)
