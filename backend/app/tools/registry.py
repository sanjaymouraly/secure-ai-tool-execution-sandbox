"""The tool registry: every tool the agent may ever call."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from . import artifacts, execution, filesystem, permissions
from .base import ToolRegistry, ToolSpec

__all__ = ["build_registry", "registry"]


def _schema(model: type[BaseModel]) -> dict[str, Any]:
    """Build the JSON schema that is handed to the model."""
    schema = model.model_json_schema()
    schema.pop("$defs", None)
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    schema["additionalProperties"] = False
    return schema


def build_registry() -> ToolRegistry:
    """Create the registry with every supported tool."""
    reg = ToolRegistry()

    reg.register(
        ToolSpec(
            name="list_files",
            title="List files",
            description=(
                "List the entries of a directory inside the approved workspace. "
                "Paths are relative to the workspace root. Read-only."
            ),
            parameters=_schema(filesystem.ListFilesInput),
            handler=filesystem.list_files,
            input_model=filesystem.ListFilesInput,
            risk="low",
            category="filesystem",
        )
    )
    reg.register(
        ToolSpec(
            name="read_file",
            title="Read file",
            description=(
                "Read a UTF-8 text file from the approved workspace. "
                "Only files with approved text extensions can be read."
            ),
            parameters=_schema(filesystem.ReadFileInput),
            handler=filesystem.read_file,
            input_model=filesystem.ReadFileInput,
            risk="low",
            category="filesystem",
        )
    )
    reg.register(
        ToolSpec(
            name="search_files",
            title="Search files",
            description=(
                "Search the contents of approved workspace files with a regular expression. Read-only."
            ),
            parameters=_schema(filesystem.SearchFilesInput),
            handler=filesystem.search_files,
            input_model=filesystem.SearchFilesInput,
            risk="low",
            category="filesystem",
        )
    )
    reg.register(
        ToolSpec(
            name="inspect_metadata",
            title="Inspect metadata",
            description=(
                "Return size, permissions, ownership and timestamps for a path in "
                "the approved workspace. Read-only."
            ),
            parameters=_schema(filesystem.InspectMetadataInput),
            handler=filesystem.inspect_metadata,
            input_model=filesystem.InspectMetadataInput,
            risk="low",
            category="filesystem",
        )
    )
    reg.register(
        ToolSpec(
            name="calculate_hash",
            title="Calculate hash",
            description=(
                "Calculate the SHA-256 (or other supported) hash of an approved "
                "workspace file so its integrity can be verified. Read-only."
            ),
            parameters=_schema(filesystem.CalculateHashInput),
            handler=filesystem.calculate_hash,
            input_model=filesystem.CalculateHashInput,
            risk="low",
            category="filesystem",
        )
    )
    reg.register(
        ToolSpec(
            name="execute_approved_command",
            title="Execute approved command",
            description=(
                "Run an allowlisted command inside a hardened, network-isolated "
                "sandbox container. Shell syntax is not supported. Requires human "
                "approval."
            ),
            parameters=_schema(execution.ExecuteCommandInput),
            handler=execution.execute_approved_command,
            input_model=execution.ExecuteCommandInput,
            risk="high",
            requires_approval=True,
            category="execution",
            mutates_state=True,
        )
    )
    reg.register(
        ToolSpec(
            name="run_python_sandboxed",
            title="Run Python (sandboxed)",
            description=(
                "Run a Python script inside a hardened, network-isolated sandbox "
                "container. The script cannot reach the host filesystem, the "
                "network or the Docker daemon. Requires human approval."
            ),
            parameters=_schema(execution.RunPythonInput),
            handler=execution.run_python_sandboxed,
            input_model=execution.RunPythonInput,
            risk="high",
            requires_approval=True,
            category="execution",
            mutates_state=True,
        )
    )
    reg.register(
        ToolSpec(
            name="create_artifact",
            title="Create artifact",
            description=(
                "Store a named text artifact produced by your analysis so it can "
                "be reviewed later. Requires human approval."
            ),
            parameters=_schema(artifacts.CreateArtifactInput),
            handler=artifacts.create_artifact,
            input_model=artifacts.CreateArtifactInput,
            risk="medium",
            requires_approval=True,
            category="artifacts",
            mutates_state=True,
        )
    )
    reg.register(
        ToolSpec(
            name="read_artifact",
            title="Read artifact",
            description="Read an artifact that was created earlier in this session.",
            parameters=_schema(artifacts.ReadArtifactInput),
            handler=artifacts.read_artifact,
            input_model=artifacts.ReadArtifactInput,
            risk="low",
            category="artifacts",
        )
    )
    reg.register(
        ToolSpec(
            name="request_permission",
            title="Request permission",
            description=(
                "Ask a human approver for permission to perform a specific action. "
                "This never grants the permission by itself."
            ),
            parameters=_schema(permissions.RequestPermissionInput),
            handler=permissions.request_permission,
            input_model=permissions.RequestPermissionInput,
            risk="medium",
            category="permissions",
        )
    )
    reg.register(
        ToolSpec(
            name="view_execution_result",
            title="View execution result",
            description="Inspect the outcome of a previous execution in this session.",
            parameters=_schema(permissions.ViewExecutionResultInput),
            handler=permissions.view_execution_result,
            input_model=permissions.ViewExecutionResultInput,
            risk="low",
            category="permissions",
        )
    )
    return reg


#: The process wide tool registry.
registry = build_registry()
