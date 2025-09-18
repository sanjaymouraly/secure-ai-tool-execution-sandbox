# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Report vulnerabilities privately through GitHub's *Security → Report a
vulnerability* form on the repository page. If that is unavailable, open a
private security advisory instead.

Please include:

* a description of the issue and the impact you believe it has,
* the exact steps to reproduce it (a proof of concept is ideal),
* the version, commit or release you tested,
* the environment (operating system, Docker version, deployment mode).

### What to expect

| Stage | Target |
| ----- | ------ |
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | within 30 working days |
| Public disclosure | coordinated with the reporter, at the latest 90 days after the first report |

We will credit the reporter in the release notes unless anonymity is
requested.

## Scope

The following are **in scope**:

* the policy engine, the hard guards and the approval workflow,
* the sandbox broker and the container hardening,
* path handling and the workspace boundary,
* authentication, authorisation, session handling and CSRF protection,
* credential handling (provider keys, the server secret),
* the audit trail and its integrity chain,
* the prompt-injection laboratory and the documented security controls.

The following are **out of scope** (but still worth reporting):

* vulnerabilities in Docker, the Linux kernel, Python, FastAPI or any
  third-party dependency that has no upstream fix available,
* a model that ignores its system prompt when the permission boundary still
  holds — that is the *expected* behaviour this project is built to contain,
* denial of service against the host that is not caused by a bug in this
  code,
* reports that require an already-compromised host, an already-compromised
  Docker daemon or the server secret.

## Security model in one paragraph

The LLM proposes tool calls; it never grants permission. Every tool call is
validated against a strict schema, evaluated by a deterministic deny-by-default
policy engine, and — where the policy says so — parked until a human approves
*that exact action*. Execution happens in a hardened, network-free container
with a read-only root filesystem, dropped capabilities, a restrictive seccomp
profile and strict resource limits. Every decision is written to an append-only
audit trail that is chained with HMAC-SHA256. Prompt-injection resistance comes
from the permission boundary, not from prompt wording or a classifier.

## Hardening advice for operators

* Change the bootstrap administrator password and `SAXIS_SECRET_KEY` before
  exposing the service.
* Set `SAXIS_PROVIDER_SECRET_KEY` so stored provider credentials are
  encrypted at rest.
* Run the Docker daemon rootless where possible, and never give the control
  plane access to more than the Docker socket it needs.
* Keep the service bound to `127.0.0.1` and put a TLS terminating reverse
  proxy in front of it (see `docs/deployment.md`).
* Do not mount the host filesystem into the workspace, and keep the workspace
  read-only for the control plane.
* Rotate provider keys and the server secret on a schedule.
* Export the audit trail regularly; the chain lets you prove it was not
  modified.
