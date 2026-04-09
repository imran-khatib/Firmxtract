"""
FirmXtract Base Classes — Module and Plugin interfaces.

Every analysis module and plugin in FirmXtract inherits from these base classes.
This ensures a consistent interface across all modules and enables the plugin
system to discover and load modules dynamically.

Usage:
    class MyAnalyzer(BaseModule):
        name = "my_analyzer"
        description = "Does something useful"

        def run(self, session: Session) -> ModuleResult:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from firmxtract.core.session import Session


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class ModuleStatus(str, Enum):
    """Execution status of a module run."""
    SUCCESS = "success"
    FAILED  = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"


@dataclass
class ModuleResult:
    """
    Standardized return value from any module's run() method.

    All modules return this — the pipeline collects them into the session.
    """
    module_name: str
    status: ModuleStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    output_path: str | None = None
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status == ModuleStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module_name,
            "status": self.status.value,
            "findings_count": len(self.findings),
            "output_path": self.output_path,
            "error": self.error,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Base Module
# ---------------------------------------------------------------------------


class BaseModule(ABC):
    """
    Abstract base class for all FirmXtract analysis modules.

    A module is a self-contained unit that:
    - Receives a Session (read access to state, output dir, config)
    - Performs one focused task (scan, extract, analyze, detect)
    - Returns a ModuleResult

    Built-in modules:  src/firmxtract/analysis/*, extraction/*, hardware/*
    Plugin modules:    src/firmxtract/plugins/builtin/*  or external packages

    Class attributes (must be set by subclasses):
        name:        Unique identifier used in reports and CLI output
        description: One-line description shown in --help and plugin list
        version:     Module version string (default "1.0.0")
        author:      Module author (default "FirmXtract")
        requires:    List of external tool names required (e.g. ["binwalk"])
    """

    name: str = "unnamed_module"
    description: str = "No description provided."
    version: str = "1.0.0"
    author: str = "FirmXtract"
    requires: list[str] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate that subclasses define required class attributes."""
        super().__init_subclass__(**kwargs)
        abstract = getattr(cls, "__abstractmethods__", None)
        if abstract is None:
            return
        if abstract:
            return
        if cls.name == "unnamed_module":
            import warnings
            warnings.warn(
                f"{cls.__name__} does not set a 'name' class attribute.",
                stacklevel=2,
            )

    @abstractmethod
    def run(self, session: "Session") -> ModuleResult:
        """
        Execute the module against the current session.

        Args:
            session: Active FirmXtract session with output dir, config,
                     and any previously extracted firmware/results.

        Returns:
            ModuleResult with status, findings, and optional output path.
        """
        ...

    def check_requirements(self) -> list[str]:
        """
        Check if required external tools are available.

        Returns:
            List of missing tool names. Empty list means all requirements met.
        """
        import shutil
        return [tool for tool in self.requires if shutil.which(tool) is None]

    def is_available(self) -> bool:
        """Return True if all required tools are present."""
        return len(self.check_requirements()) == 0

    def __repr__(self) -> str:
        return f"<Module {self.name} v{self.version}>"


# ---------------------------------------------------------------------------
# Base Plugin (extends BaseModule with metadata + hook system)
# ---------------------------------------------------------------------------


class HookPoint(str, Enum):
    """
    Pipeline hook points where plugins can inject behavior.

    PRE_EXTRACT:   Before firmware extraction begins
    POST_EXTRACT:  After firmware extraction completes
    PRE_ANALYZE:   Before binwalk analysis
    POST_ANALYZE:  After binwalk analysis
    PRE_SECRETS:   Before secrets scan
    POST_SECRETS:  After secrets scan
    POST_REPORT:   After report is written
    """
    PRE_EXTRACT  = "pre_extract"
    POST_EXTRACT = "post_extract"
    PRE_ANALYZE  = "pre_analyze"
    POST_ANALYZE = "post_analyze"
    PRE_SECRETS  = "pre_secrets"
    POST_SECRETS = "post_secrets"
    POST_REPORT  = "post_report"


class BasePlugin(BaseModule):
    """
    Abstract base class for FirmXtract plugins.

    Plugins extend BaseModule with:
    - Hook registration: run at specific pipeline stages
    - Enable/disable toggle
    - Priority ordering (lower = runs first)

    To create a plugin:

        class MyPlugin(BasePlugin):
            name        = "my_plugin"
            description = "Scans for CVEs in extracted packages"
            hooks       = [HookPoint.POST_ANALYZE]
            priority    = 50

            def run(self, session: Session) -> ModuleResult:
                # your logic here
                return ModuleResult(
                    module_name=self.name,
                    status=ModuleStatus.SUCCESS,
                    findings=[...],
                )

    Install as a plugin by adding to pyproject.toml:

        [project.entry-points."firmxtract.plugins"]
        my_plugin = "my_package.my_module:MyPlugin"
    """

    hooks: list[HookPoint] = []
    priority: int = 100       # lower number = higher priority
    enabled: bool = True

    def on_load(self) -> None:
        """Called once when the plugin is loaded. Override for setup."""
        pass

    def on_unload(self) -> None:
        """Called when the plugin is unloaded. Override for cleanup."""
        pass

    def __repr__(self) -> str:
        hooks_str = ", ".join(h.value for h in self.hooks) or "standalone"
        return f"<Plugin {self.name} v{self.version} hooks=[{hooks_str}]>"
