"""Policy engine and hard guard tests.

These tests exercise the real engine - no mocked allow/deny results.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.commands import CommandAllowlist, CommandRule
from app.core.paths import SafePathResolver
from app.policy.engine import PolicyEngine, argument_signature, canonical_arguments
from app.policy.guards import GuardContext, evaluate_guards
from app.policy.schema import PolicyDocument


@pytest.fixture()
def resolver(tmp_path: Path) -> SafePathResolver:
    root = tmp_path / "workspace"
    (root / "documents").mkdir(parents=True)
    (root / "documents" / "report.md").write_text("# report", encoding="utf-8")
    (root / "protected").mkdir()
    (root / "protected" / "secret.txt").write_text("secret", encoding="utf-8")
    return SafePathResolver([root])


@pytest.fixture()
def allowlist() -> CommandAllowlist:
    return CommandAllowlist(
        [
            CommandRule(name="ls", max_args=4),
            CommandRule(name="cat", max_args=4),
            CommandRule(name="curl", max_args=4),
        ]
    )


@pytest.fixture()
def engine(resolver: SafePathResolver, allowlist: CommandAllowlist) -> PolicyEngine:
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    return PolicyEngine.from_file(policy_path, path_resolver=resolver, command_allowlist=allowlist)


def test_default_policy_loads(engine: PolicyEngine) -> None:
    assert engine.version == "2.0.0"
    assert len(engine.document.rules) > 5
    assert engine.document.defaults.effect == "deny"


def test_read_of_approved_document_is_allowed(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "documents/report.md"})
    assert decision.allowed
    assert decision.effect == "allow"
    assert decision.source == "policy"


def test_protected_path_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "protected/secret.txt"})
    assert not decision.allowed
    assert decision.effect == "deny"
    assert decision.rule_id == "deny-protected-workspace-paths"
    assert "protected" in decision.reason.lower()


def test_unknown_tool_is_denied_by_default(engine: PolicyEngine) -> None:
    decision = engine.evaluate("rm_rf", {"value": 1})
    assert not decision.allowed
    assert decision.source == "default"


def test_absolute_path_is_denied_by_the_guard(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "/etc/passwd"})
    assert not decision.allowed
    assert decision.source == "guard"
    assert decision.rule_id.startswith("guard:")


def test_traversal_is_denied_by_the_guard(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "../../etc/passwd"})
    assert not decision.allowed
    assert decision.source == "guard"


def test_command_execution_requires_approval(engine: PolicyEngine) -> None:
    decision = engine.evaluate("execute_approved_command", {"command": "ls documents"})
    assert not decision.allowed
    assert decision.effect == "require_approval"
    assert decision.requires_approval


def test_network_command_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("execute_approved_command", {"command": "curl http://x"})
    assert not decision.allowed
    assert decision.effect == "deny"
    assert decision.rule_id == "deny-network-commands"


def test_destructive_command_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("execute_approved_command", {"command": "rm -rf /"})
    assert not decision.allowed
    assert decision.rule_id in {"deny-destructive-commands", "guard:command_unsafe"}


def test_shell_metacharacters_are_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("execute_approved_command", {"command": "ls; id"})
    assert not decision.allowed
    assert decision.source == "guard"


def test_python_script_with_os_import_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("run_python_sandboxed", {"code": "import os\nprint(os.environ)"})
    assert not decision.allowed
    assert decision.rule_id == "guard:python_unsafe"


def test_network_argument_is_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("run_python_sandboxed", {"code": "print(1)", "url": "http://evil"})
    assert not decision.allowed
    assert decision.rule_id == "guard:network_denied"


def test_oversized_arguments_are_denied(engine: PolicyEngine) -> None:
    decision = engine.evaluate("search_files", {"pattern": "a", "path": "x" * 200_000})
    assert not decision.allowed
    assert decision.rule_id == "guard:argument_too_large"


def test_artifact_name_validation(engine: PolicyEngine) -> None:
    decision = engine.evaluate("create_artifact", {"name": "../escape.txt", "content": "x"})
    assert not decision.allowed
    assert decision.rule_id == "guard:artifact_name_invalid"


def test_explanation_is_populated(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "protected/secret.txt"})
    assert decision.explanation
    assert any("deny-protected-workspace-paths" in line for line in decision.explanation)


def test_policy_version_and_revision_are_reported(engine: PolicyEngine) -> None:
    decision = engine.evaluate("read_file", {"path": "documents/report.md"})
    assert decision.policy_version == engine.version
    assert decision.policy_revision == engine.revision


def test_rules_are_evaluated_by_priority(engine: PolicyEngine) -> None:
    priorities = [rule["priority"] for rule in engine.rules()]
    assert priorities == sorted(priorities, reverse=True)


def test_invalid_policy_document_is_rejected(resolver, allowlist) -> None:
    with pytest.raises(Exception):
        PolicyDocument.model_validate({"version": "1", "rules": [{"id": "x", "effect": "maybe"}]})


def test_duplicate_rule_ids_are_rejected() -> None:
    with pytest.raises(Exception):
        PolicyDocument.model_validate(
            {
                "version": "1",
                "rules": [
                    {"id": "dup", "effect": "allow"},
                    {"id": "dup", "effect": "deny"},
                ],
            }
        )


def test_argument_signature_is_stable_and_specific() -> None:
    first = argument_signature("read_file", {"path": "a.txt", "max_bytes": 10})
    second = argument_signature("read_file", {"max_bytes": 10, "path": "a.txt"})
    third = argument_signature("read_file", {"path": "b.txt", "max_bytes": 10})
    assert first == second
    assert first != third


def test_canonical_arguments_drop_volatile_fields() -> None:
    canonical = canonical_arguments({"path": "a", "trace_id": "x", "request_id": "y"})
    assert canonical == {"path": "a"}


def test_symlink_laundering_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    (root / "documents").mkdir(parents=True)
    (root / "protected").mkdir()
    (root / "protected" / "secret.txt").write_text("secret", encoding="utf-8")
    (root / "documents" / "link.txt").symlink_to(root / "protected" / "secret.txt")
    resolver = SafePathResolver([root])
    allowlist = CommandAllowlist()
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    engine = PolicyEngine.from_file(policy_path, path_resolver=resolver, command_allowlist=allowlist)

    decision = engine.evaluate("read_file", {"path": "documents/link.txt"})
    assert not decision.allowed
    assert decision.rule_id == "deny-protected-workspace-paths"


def test_session_grant_allows_only_the_exact_action(engine: PolicyEngine) -> None:
    from app.policy.engine import _grant_matches

    class Grant:
        id = "g1"
        tool_name = "execute_approved_command"
        argument_hash = argument_signature("execute_approved_command", {"command": "ls"})
        uses_remaining = -1
        expires_at = None

    grant = Grant()
    assert _grant_matches(grant, "execute_approved_command", grant.argument_hash)
    assert not _grant_matches(grant, "execute_approved_command", "other-hash")
    assert not _grant_matches(grant, "read_file", grant.argument_hash)


def test_guard_context_is_required_for_network(resolver, allowlist) -> None:
    context = GuardContext(path_resolver=resolver, command_allowlist=allowlist)
    violations = evaluate_guards("run_python_sandboxed", {"url": "http://x"}, context)
    assert any(v.code == "network_denied" for v in violations)
