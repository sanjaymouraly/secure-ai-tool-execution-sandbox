# Security controls

This document lists the controls that are actually implemented, where they
live and how they are verified. Anything that is *not* implemented is
documented in `docs/limitations.md` instead.

## 1. Authorisation

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Deny by default | `PolicyDocument.defaults.effect = "deny"`; the engine falls through to it when no rule matches | `tests/test_policy_engine.py::test_unknown_tool_is_denied_by_default` |
| Deterministic evaluation | Rules are sorted by descending `priority` then ascending `id`; the first match decides | `tests/test_policy_engine.py::test_rules_are_evaluated_by_priority` |
| Hard guards before policy | `evaluate_guards()` runs first in `PolicyEngine.evaluate` | `tests/test_policy_engine.py::test_absolute_path_is_denied_by_the_guard` |
| Policy cannot relax a guard | The guard set is code, not configuration | `tests/test_policy_engine.py` |
| Strict policy schema | `PolicyDocument` forbids unknown fields, rejects duplicate rule ids and invalid effects | `tests/test_policy_engine.py::test_invalid_policy_document_is_rejected` |
| Policy editing restricted | `POST /api/v1/policies/current` requires the `admin` role; every change is versioned and audited | `tests/test_api.py::test_policy_editor_requires_admin` |
| Subject scoping | Rules can be scoped by user, role, agent, project and session | `backend/app/policy/schema.py` |
| Permission expiry and revocation | Approvals expire; session grants can be revoked per session or globally | `tests/test_broker.py::test_revoked_grant_blocks_execution` |
| Human-readable explanation | Every decision carries the matched rule, the matched constraints and a step-by-step explanation | `tests/test_policy_engine.py::test_explanation_is_populated` |

## 2. Approvals

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Allow once / allow for session / deny | `ApprovalService.decide` | `tests/test_broker.py` |
| Approval bound to the exact action | SHA-256 over the canonical tool name and arguments (`argument_signature`) | `tests/test_broker.py::test_approval_scope_cannot_be_widened` |
| Re-validation immediately before execution | `approved_execution_allowed` is called by the broker before the handler runs | `tests/test_broker.py::test_approval_scope_cannot_be_widened` |
| Separation of duties | The API refuses to let the requester decide their own approval | `backend/app/api/routes/approvals.py` |
| Expiry | An expired approval is refused and marked `expired` | `backend/app/services/approvals.py` |
| Expiry of session grants | Grants carry `expires_at` and are re-checked on every evaluation | `backend/app/policy/engine.py` |

## 3. Filesystem

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Traversal rejection | `..` components, percent-encoding, NUL bytes and backslashes are rejected before any I/O | `tests/test_paths.py::test_traversal_is_rejected` |
| Absolute escape rejection | The resolved path must be inside an approved root | `tests/test_paths.py::test_absolute_escape_is_rejected` |
| Symlink escape rejection | `realpath` containment plus `O_NOFOLLOW` on the final open | `tests/test_paths.py::test_symlink_outside_workspace_is_rejected` |
| Symlink laundering | The policy matches the **resolved** path, not only the requested one | `tests/test_policy_engine.py::test_symlink_laundering_is_denied` |
| Hard-link refusal | Files with `st_nlink > 1` are refused | `tests/test_paths.py::test_hardlink_is_refused` |
| Time-of-check/time-of-use | Reads use `O_NOFOLLOW`; writes use `O_EXCL` plus `os.replace` | `tests/test_paths.py::test_write_atomic_refuses_existing_file` |
| Size limits | Reads, writes, staging and listing all have explicit limits | `app/core/config.py` |
| Extension allowlist | `read_file` only accepts approved text extensions | `backend/policies/default.yaml` |
| No host mount | Approved files are **copied** into a per-job directory | `app/tools/execution.py::_stage_approved_workspace` |

## 4. Command execution

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| No shell | `shlex.split` + `execvpe`; there is no `subprocess(..., shell=True)` anywhere | `tests/test_commands.py` |
| Program allowlist | `CommandAllowlist`; an unknown program is refused | `tests/test_commands.py::test_non_allowlisted_commands_are_rejected` |
| Metacharacter rejection | `| & ; < > $ ( ) \` newline` are rejected in the command string | `tests/test_commands.py::test_shell_metacharacters_are_rejected` |
| Absolute program path refused | `/bin/ls` is rejected | `tests/test_commands.py::test_absolute_program_path_is_rejected` |
| Path separator refused | `./ls` is rejected | `tests/test_commands.py::test_path_separator_in_program_is_rejected` |
| Dangerous flags refused | `--output`, `--exec`, `--require`, … are refused | `tests/test_commands.py::test_flag_smuggling_is_rejected` |
| Argument count and length limits | Enforced per command | `tests/test_commands.py::test_too_many_arguments_are_rejected` |
| Policy-level command deny | `deny-network-commands`, `deny-destructive-commands` | `tests/test_policy_engine.py` |

## 5. Sandbox

Every flag below is applied by `DockerSandboxBackend.build_command`.

| Control | Flag | Verified by |
| ------- | ---- | ------------ |
| Ephemeral container | `--rm` | `tests/test_sandbox.py::test_no_container_is_left_behind` |
| Read-only root filesystem | `--read-only` | `tests/test_sandbox.py::test_root_filesystem_is_read_only` |
| All capabilities dropped | `--cap-drop ALL` | `tests/test_sandbox.py::test_execution_runs_as_non_root` |
| No privilege escalation | `--security-opt no-new-privileges` | `tests/test_sandbox.py` |
| Restrictive seccomp | `--security-opt seccomp=<profile>` | `tests/test_sandbox.py::test_network_is_denied` |
| AppArmor | `--security-opt apparmor=docker-default` | `tests/test_sandbox.py::test_execution_runs_as_non_root` |
| No network | `--network none` | `tests/test_sandbox.py::test_network_is_denied` |
| No DNS | no resolver in the namespace | `tests/test_sandbox.py::test_dns_resolution_fails` |
| Unprivileged uid | `--user 10001:10001` | `tests/test_sandbox.py::test_execution_runs_as_non_root` |
| Private cgroup namespace | `--cgroupns private` | `DockerSandboxBackend.build_command` |
| CPU limit | `--cpus` | `DockerSandboxBackend.build_command` |
| Memory limit | `--memory`, `--memory-swap` | `tests/test_sandbox.py::test_memory_limit_is_enforced` |
| PID limit | `--pids-limit` | `tests/test_sandbox.py::test_process_limit_is_enforced` |
| File descriptor limit | `--ulimit nofile=1024:1024` | `DockerSandboxBackend.build_command` |
| File size limit | `--ulimit fsize` | `DockerSandboxBackend.build_command` |
| Writable scratch only | `--tmpfs /tmp:rw,noexec,nosuid,nodev` | `DockerSandboxBackend.build_command` |
| Two bind mounts only | `--mount` input (ro) and output (rw) | `tests/test_sandbox.py::test_host_filesystem_is_not_reachable` |
| No Docker socket | never mounted | `tests/test_sandbox.py::test_docker_socket_is_not_mounted` |
| No host namespaces | no `--pid`, `--net`, `--ipc`, `--uts` host modes | `DockerSandboxBackend.build_command` |
| No privileged mode | never used | `DockerSandboxBackend.build_command` |
| No devices | no `--device` | `DockerSandboxBackend.build_command` |
| Wall-clock limit | `signal.alarm` in the entry point plus a broker timeout | `tests/test_sandbox.py::test_timeout_is_enforced` |
| Output size limit | truncated by the broker | `tests/test_sandbox.py::test_output_is_truncated` |
| Clean-up | `--rm`, `docker rm -f` on timeout, per-job directories removed | `tests/test_sandbox.py::test_no_container_is_left_behind` |

The seccomp profile is generated from Docker's own default profile by
`scripts/build_seccomp_profile.py` and additionally removes the networking,
namespace, tracing, eBPF and kernel-module syscalls.

## 6. AI provider and secrets

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Environment-only secrets | `SAXIS_SECRET_KEY`, `SAXIS_PROVIDER_SECRET_KEY` | `app/core/config.py` |
| Encryption at rest | Fernet (AES-128-CBC + HMAC) for stored provider keys | `app/services/secrets.py` |
| No clear-text storage | The API refuses to store a key without an encryption key | `backend/app/api/routes/providers.py` |
| No secrets in the sandbox | The environment is scrubbed before the worker starts | `tests/test_sandbox.py::test_secrets_are_not_present_in_the_sandbox` |
| Redaction | Logs, audit records, API responses and tool results are scrubbed | `tests/test_audit.py::test_secrets_are_redacted_in_the_audit_trail` |
| No secrets in the browser | The API only returns a short hint (`sk-…-abc`) | `backend/app/api/routes/providers.py` |
| Cost control | Per-session and per-day budgets, token accounting, a published price table | `tests/test_providers.py::test_budget_guard_blocks_when_exhausted` |
| Error classification | 401, 429, 400, timeouts and malformed responses are distinguished | `tests/test_providers.py` |

## 7. Authentication and session handling

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Argon2id password hashing | `app/core/security.py` | `tests/test_api.py` |
| Account lockout | 10 failed attempts lock the account | `backend/app/api/routes/auth.py` |
| HttpOnly session cookie | `sax_session` | `tests/test_api.py::test_login_sets_session_cookies` |
| CSRF double submit | A random token is embedded in the signed session and echoed in `X-CSRF-Token` | `tests/test_api.py::test_csrf_is_enforced_for_cookie_authentication` |
| Role based access control | `admin`, `approver`, `analyst`, `viewer` | `tests/test_api.py` |
| Rate limiting | Per user/address, plus a stricter login limiter | `backend/app/api/deps.py` |
| Origin restrictions | CORS allow-list | `backend/app/main.py` |
| Security headers | CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy` | `tests/test_api.py::test_security_headers_are_present` |
| Generic error payloads | Unhandled errors return a sanitised body and are logged | `backend/app/main.py` |

## 8. Audit trail

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Append-only | Rows are only inserted; there is no update or delete path in the application | `app/services/audit.py` |
| Integrity chain | HMAC-SHA256 over the canonical record plus the previous hash | `tests/test_audit.py::test_audit_events_are_chained` |
| Tamper detection | The verification endpoint recomputes the chain | `tests/test_audit.py::test_tampering_is_detected` |
| Gap detection | A missing sequence is reported | `tests/test_audit.py::test_sequence_gaps_are_detected` |
| Redaction | Credentials never enter the trail | `tests/test_audit.py::test_secrets_are_redacted_in_the_audit_trail` |
| Search and export | Filters, JSON and CSV export, retention | `backend/app/api/routes/audit.py` |
| Trace correlation | Every record carries a trace id | `backend/app/api/routes/audit.py` |

## 9. Prompt-injection containment

| Control | Implementation | Verified by |
| ------- | -------------- | ------------ |
| Untrusted marking | Tool results are stored with `is_untrusted = True` and rendered with an `untrusted` badge | `backend/app/orchestrator/agent.py` |
| No authority in content | The model cannot change the policy or grant a permission | `attack-002`, `attack-014`, `attack-024` |
| Instruction override defence | The policy decides, not the model | `attack-001`, `attack-003`, `attack-022` |
| Obfuscation defence | Base64 payloads are just text; the encoded payload does not change the decision | `attack-005` |
| Regression suite | 34 scenarios, executed against the real stack on every test run | `tests/test_attack_lab.py` |
| False-positive measurement | 10 benign workflows must still succeed | `tests/test_attack_lab.py::test_statistics_are_computed` |

## 10. Operational controls

| Control | Implementation |
| ------- | -------------- |
| Health and readiness probes | `/health`, `/ready` (checks the database and the sandbox) |
| Metrics | `/metrics` |
| Graceful shutdown | The lifespan handler cleans up the sandbox containers |
| Structured logging | JSON logs with credential redaction |
| Request correlation | Every request gets an `X-Request-ID` |
| Bounded queues | Step limit, per-step tool-call limit, provider timeout, sandbox timeout |
| Cleanup and recovery | Per-job directories are removed; orphaned containers are removed on timeout |
| Explicit failure states | A missing Docker daemon produces a clear setup error, never a silent fallback |
