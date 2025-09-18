"""Application container.

A single place that wires the policy engine, the sandbox backend, the tool
registry, the broker and the AI providers together.  The container is created
once at startup and shared by the API routes.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from ..core.commands import CommandAllowlist
from ..core.config import Settings, get_settings
from ..core.paths import SafePathResolver
from ..db.models import ProviderProfile
from ..policy.engine import PolicyEngine, PolicyLoadError
from ..policy.guards import GuardContext
from ..providers.base import Provider, ProviderConfiguration
from ..providers.registry import build_provider
from ..sandbox.base import SandboxBackend
from ..sandbox.local_backend import build_backend
from ..services.approvals import ApprovalService
from ..services.audit import AuditService
from ..services.broker import DEFAULT_COMMAND_RULES, ToolBroker
from ..services.workspace import ArtifactStore, WorkspaceService
from ..tools.registry import registry as tool_registry

logger = logging.getLogger(__name__)


class Container:
    """Holds the long lived services of the application."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        # A re-entrant lock is required: building the broker acquires the
        # policy engine and the sandbox backend, which both take this lock.
        self._lock = threading.RLock()
        self._policy_engine: PolicyEngine | None = None
        self._sandbox: SandboxBackend | None = None
        self._broker: ToolBroker | None = None
        self.audit = AuditService(self.settings)
        self.approvals = ApprovalService(self.settings)
        self.path_resolver = SafePathResolver([self.settings.workspace_root])
        self.command_allowlist = CommandAllowlist(DEFAULT_COMMAND_RULES)
        self.workspace = WorkspaceService(self.settings.workspace_root, self.path_resolver)
        self.artifact_store = ArtifactStore(
            self.settings.artifact_root,
            max_bytes=self.settings.max_artifact_bytes,
            max_per_session=self.settings.max_artifact_count_per_session,
        )
        self.tool_registry = tool_registry

    # -------------------------------------------------------------- policy
    @property
    def policy_engine(self) -> PolicyEngine:
        with self._lock:
            if self._policy_engine is None:
                self._policy_engine = self._load_policy()
            return self._policy_engine

    def _load_policy(self) -> PolicyEngine:
        guard_context = GuardContext(
            path_resolver=self.path_resolver,
            command_allowlist=self.command_allowlist,
            max_argument_bytes=65_536,
            max_path_depth=32,
            allowed_network_hosts=frozenset(self.settings.sandbox_allow_network_exceptions),
            network_enabled=not self.settings.sandbox_deny_network,
        )
        try:
            return PolicyEngine.from_file(
                self.settings.policy_file,
                path_resolver=self.path_resolver,
                command_allowlist=self.command_allowlist,
                guard_context=guard_context,
            )
        except PolicyLoadError:
            logger.exception(
                "The policy document at %s could not be loaded. Refusing to start with an "
                "unvalidated policy.",
                self.settings.policy_file,
            )
            raise

    def reload_policy(self) -> PolicyEngine:
        """Re-read the policy document from disk."""
        with self._lock:
            self._policy_engine = self._load_policy()
            return self._policy_engine

    def set_policy_engine(self, engine: PolicyEngine) -> None:
        """Install a policy engine (used by the policy editor)."""
        with self._lock:
            self._policy_engine = engine
            self._rebuild_broker()

    # ------------------------------------------------------------- sandbox
    @property
    def sandbox(self) -> SandboxBackend:
        with self._lock:
            if self._sandbox is None:
                self._sandbox = build_backend(self.settings)
            return self._sandbox

    def set_sandbox(self, backend: SandboxBackend) -> None:
        with self._lock:
            self._sandbox = backend
            self._rebuild_broker()

    # -------------------------------------------------------------- broker
    @property
    def broker(self) -> ToolBroker:
        with self._lock:
            if self._broker is None:
                self._broker = self._build_broker()
            return self._broker

    def _build_broker(self) -> ToolBroker:
        return ToolBroker(
            policy_engine=self.policy_engine,
            sandbox=self.sandbox,
            tool_registry=self.tool_registry,
            audit=self.audit,
            approvals=self.approvals,
            settings=self.settings,
            path_resolver=self.path_resolver,
            command_allowlist=self.command_allowlist,
            artifact_store=self.artifact_store,
            workspace=self.workspace,
        )

    def _rebuild_broker(self) -> None:
        self._broker = self._build_broker()

    # ----------------------------------------------------------- providers
    def default_provider_configuration(self) -> ProviderConfiguration:
        """Return the provider configuration from the environment."""
        settings = self.settings
        api_key = settings.provider_api_key or ""
        if not api_key:
            import os

            api_key = os.getenv(settings.provider_key_env_var, "")
        return ProviderConfiguration(
            provider_type=settings.default_provider,
            base_url=settings.provider_base_url,
            api_key=api_key,
            model=settings.provider_model,
            timeout_seconds=settings.provider_timeout_seconds,
            max_retries=settings.provider_max_retries,
            max_tokens=settings.provider_max_tokens,
            temperature=settings.provider_temperature,
        )

    def build_provider(self, config: ProviderConfiguration | None = None) -> Provider:
        """Instantiate a provider from a configuration or the stored profile."""
        if config is None:
            config = self.default_provider_configuration()
        return build_provider(config, self.settings)

    def provider_from_profile(self, profile: ProviderProfile) -> Provider:
        """Instantiate a provider from a stored (decrypted) profile."""
        from ..services.secrets import decrypt_secret

        api_key = ""
        if profile.api_key_encrypted:
            try:
                api_key = decrypt_secret(profile.api_key_encrypted, self.settings)
            except Exception:
                logger.warning("Stored API key for profile %s could not be decrypted", profile.name)
        config = ProviderConfiguration(
            provider_type=profile.provider_type,
            base_url=profile.base_url,
            api_key=api_key,
            model=profile.model,
            timeout_seconds=int(
                profile.options.get("timeout_seconds", self.settings.provider_timeout_seconds)
            ),
            max_retries=int(profile.options.get("max_retries", self.settings.provider_max_retries)),
            max_tokens=int(profile.options.get("max_tokens", self.settings.provider_max_tokens)),
            temperature=float(profile.options.get("temperature", self.settings.provider_temperature)),
            extra_headers=dict(profile.extra_headers or {}),
            options=dict(profile.options or {}),
        )
        return build_provider(config, self.settings)

    # -------------------------------------------------------------- status
    async def health(self) -> dict[str, Any]:
        """Aggregate the health of the system."""
        sandbox_status = await self.sandbox.status()
        return {
            "policy": {
                "version": self.policy_engine.version,
                "revision": self.policy_engine.revision,
                "rules": len(self.policy_engine.document.rules),
            },
            "sandbox": sandbox_status.to_dict(),
            "tools": len(self.tool_registry.all()),
            "provider": {
                "type": self.settings.default_provider,
                "model": self.settings.provider_model,
            },
        }


_container: Container | None = None
_container_lock = threading.Lock()


def get_container() -> Container:
    """Return the process wide container."""
    global _container
    with _container_lock:
        if _container is None:
            _container = Container()
        return _container


def reset_container() -> None:
    """Drop the container (used by tests)."""
    global _container
    with _container_lock:
        _container = None
