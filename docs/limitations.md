# Limitations

This document is deliberately honest. It lists what the project **does not**
guarantee, what was **not** implemented, and what could not be **verified** in
the development environment.

## 1. Container isolation is not a kernel boundary

Ordinary Docker containers are **not** a security boundary against a kernel
exploit or a container runtime vulnerability. The sandbox in this project
applies many layers — a read-only root filesystem, dropped capabilities,
`no-new-privileges`, a restrictive seccomp profile, AppArmor, a private cgroup
namespace, an unprivileged uid, no network and strict resource limits — and
that raises the cost of an escape considerably. It does **not** make an escape
impossible.

For untrusted third-party code, use a stronger backend:

* **gVisor** (`runsc`) — intercepts the syscall surface in user space.
* **Firecracker / Cloud Hypervisor** — a microVM with its own kernel.
* **Firecracker + `kata-containers`** — microVM with a container-like
  interface.

The `SandboxBackend` interface in `backend/app/sandbox/base.py` exists exactly
for this: implement it and register the backend, and the rest of the system
works unchanged. The `isolated` flag on the backend is propagated to every
execution record so that a simulated backend can never be mistaken for a real
one.

## 2. The `local-simulated` backend provides no isolation

`SAXIS_SANDBOX_BACKEND=local-simulated` runs the approved program **directly
on the host**. It is:

* never selected automatically — the Docker backend is the default and a
  missing Docker daemon produces a clear setup error,
* tagged with `backend = "local-simulated"` and `isolated = False` in every
  execution record, the audit trail and the dashboard,
* refused outright in `production` mode by the settings validator.

It exists so that the test-suite and the offline demo work on a machine
without Docker. It must never be used with untrusted input.

## 3. Rootless Docker is recommended but not enforced

The broker applies `--userns keep-id` when the daemon runs rootless. On a
rootful daemon the container still runs as an unprivileged uid inside its own
namespaces, but the daemon itself has root on the host, and a daemon
compromise is a host compromise. The dashboard shows the current posture and
warns when the daemon is not rootless.

## 4. The audit chain provides tamper *evidence*, not tamper *prevention*

The chain is computed with HMAC-SHA256 keyed with `SAXIS_SECRET_KEY`. It
detects modification and deletion of records by anyone who does not also hold
that secret. It does **not** prevent them:

* an operator with write access to the database can rewrite history *and* the
  chain, unless the server secret is also compromised;
* the records live in the same database as the application data, so an
  operator with database access can delete them;
* there is no WORM storage, no external anchoring and no periodic export of
  the chain head to an append-only store.

Mitigations available today: export the trail regularly
(`GET /api/v1/audit/export`) and keep the exports in an append-only store
yourself. A future improvement would be to anchor the chain head periodically
to an external, write-once store.

## 5. The rate limiter is per process

`app/api/deps.py` implements a sliding-window limiter in process memory. With
several replicas behind a load balancer the effective global limit is the
sum of the per-process limits, and the login limiter can be bypassed by
spreading requests across replicas. A shared store (Redis) is required for a
multi-replica deployment; the limiter interface is small enough to swap.

## 6. The agent transcript is sent to the model provider

When a real provider is configured, the system prompt, the user request and
the **content of every tool result the policy allowed** are sent to that
provider. That is inherent to the product: an LLM provider can only answer
questions about data it can see.

Consequences an operator must accept:

* a provider may retain the transcript — use a provider with a suitable data
  processing agreement, or a local runtime such as Ollama;
* a compromised provider sees the same data the agent was allowed to see, but
  **not** more: the policy decides what the agent can read, so the provider
  only ever receives authorised content;
* the provider never receives the policy document, the approval table, the
  audit trail, the server secret or the workspace paths that were denied.

## 7. Small local models are unreliable

The deterministic offline simulation provider is completely predictable and
is used for the automated tests. A small local model (for example
`qwen2.5:1.5b` through Ollama) is good enough for the demonstration
workflows but may return an empty turn or an unusable tool call. The
orchestrator handles an empty final message explicitly, and the trace always
shows the raw tool calls so the operator can see what happened.

## 8. The prompt-based tool calling fallback is a fallback

For models whose runtime does not support the native `tools` parameter, the
adapter describes the tools in the system prompt and parses a JSON tool call
out of the reply. This is less reliable than native tool calling and is
clearly labelled in the provider configuration
(`force_prompt_tools = True`).

## 9. Cost figures are estimates

The price table in `app/providers/registry.py` contains published list prices.
The dashboard labels every figure as an estimate. Provider billing may differ
(tiers, cached input, batch discounts, regional pricing). The budget guard
uses the same estimates, so a budget is an approximation, not a hard cap on
spending.

## 10. Incomplete or simplified areas

* **Streaming responses** are plumbed through the provider interface, but the
  dashboard polls the session trace instead of consuming a stream.
* **The policy editor** validates, stores, versions and installs a policy
  document, and the dashboard renders the evaluation order. It is not a
  full graphical rule builder, and the JSON/YAML editor is the intended
  workflow.
* **Project-scoped permissions** are supported by the policy schema
  (`subjects.projects`) and by the data model, but the dashboard does not yet
  offer a project management screen.
* **Multi-user registration** is disabled by default
  (`SAXIS_ALLOW_REGISTRATION=false`); accounts are created by an administrator.
  There is no password reset flow — an administrator resets the password
  directly.
* **Audit retention** is applied by an explicit administrative action
  (`DELETE /api/v1/audit/retention`), not by a background job.
* **The `request_permission` tool** creates an approval request but does not
  block the agent until a human answers; the agent is told the request is
  pending.

## 11. Platform-specific limitations

### Windows

* Docker Desktop with **Linux containers** is required. The Windows container
  image format cannot provide the Linux namespaces, capabilities and seccomp
  behaviour the sandbox relies on.
* The file paths in the workspace are POSIX-style inside the container; the
  broker translates them.
* The `local-simulated` backend uses `preexec_fn`, which is POSIX-only. It
  is not supported on Windows and the test-suite falls back to the Docker
  backend there.

### Linux

* The seccomp profile assumes a modern kernel. On an old kernel some
  syscalls in the profile are unknown and are ignored, which weakens the
  filter slightly.
* AppArmor is optional. Without it the seccomp profile and the namespace
  configuration are the only syscall-level controls.

### macOS

* Docker Desktop runs a Linux VM. The isolation is then the isolation of that
  VM, which is stronger than a local container but weaker than a dedicated
  microVM. The project is **not** tested on macOS in CI.

## 12. Docker-out-of-Docker constraints in the Compose deployment

When the control plane itself runs in a container and starts sandbox
containers through the mounted Docker socket, the **daemon** resolves every
bind mount source on the *host*, not inside the control plane container. Two
consequences are handled by the shipped Compose files:

* the per-job workspace directory (`/tmp/saxis-jobs`) is mounted at the **same
  absolute path** on the host and in the container, and a one-shot
  `job-root-init` service creates it with the sticky bit so that both the
  container user and a local user can work with it;
* the hardened seccomp profile is mounted at the **same absolute path**
  (`/etc/saxis/seccomp.json`) on the host and in the container, because the
  daemon reads the profile from the host filesystem.

If you change either path, change it in both places.

In addition, the control plane container needs the group that owns
`/var/run/docker.sock`. Set `SAXIS_DOCKER_GID` to the output of
`stat -c '%g' /var/run/docker.sock`; the setup script detects it
automatically.

## 13. What was not verified in the development environment

* The project was developed and verified on Ubuntu 22.04 with Docker Engine
  29.8, Python 3.12 and Node 22.
* The Compose stack was verified end to end: the images build, the control
  plane starts the sandbox containers through the mounted socket, an approved
  command really executes in an isolated container and the full
  prompt-injection catalogue passes against the containerised deployment.
* Container-to-container traffic on a user-defined Docker bridge was **not**
  routable in the nested container environment used for the development, so
  the nginx → backend hop of the Compose stack could not be exercised there.
  The API was verified through the published port instead, and the Compose
  files are standard and valid (`docker compose config` passes). On a normal
  Docker installation the bridge network is routable.
* The Windows path was validated by static review and by the Windows CI job
  (imports and the platform-independent tests). The full Docker-on-Windows
  path was **not** executed in this environment.
* The PostgreSQL deployment path was **not** exercised end to end; the
  schema is portable SQLAlchemy and the connection string is configurable, but
  treat the first PostgreSQL deployment as unverified.
* The gVisor and microVM backends are **not** implemented. The interface
  exists and is documented; the recommendation above is not a feature of this
  release.
* Load and soak testing was not performed. The rate limiter and the queue
  behaviour are designed for it, not measured.
