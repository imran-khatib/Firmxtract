"""
FirmXtract Plugin Loader.

Discovers and loads plugins from three sources (in priority order):
  1. Built-in plugins:  src/firmxtract/plugins/builtin/
  2. User plugins:      ~/.firmxtract/plugins/
  3. Installed plugins: Python packages that declare entry point
                        [firmxtract.plugins] in their pyproject.toml

Usage:
    loader = PluginLoader()
    plugins = loader.discover_all()
    for plugin in plugins:
        print(plugin.name, plugin.description)

To install a third-party plugin:
    pip install firmxtract-plugin-cve-scanner

    # pyproject.toml of the plugin package:
    [project.entry-points."firmxtract.plugins"]
    cve_scanner = "firmxtract_cve:CVEScannerPlugin"
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path

from firmxtract.core.base import BasePlugin
from firmxtract.utils.logger import get_logger

log = get_logger(__name__)

# Entry point group name for installed plugins
PLUGIN_ENTRY_POINT_GROUP = "firmxtract.plugins"

# User plugin directory
USER_PLUGIN_DIR = Path.home() / ".firmxtract" / "plugins"


class PluginLoader:
    """
    Discovers, loads, and validates FirmXtract plugins.

    Plugins are BasePlugin subclasses loaded from:
      - Built-in directory (ships with FirmXtract)
      - User directory (~/.firmxtract/plugins/)
      - Installed Python packages via entry_points

    All loaded plugins are validated before being returned.
    Invalid or broken plugins are logged and skipped.
    """

    def __init__(self) -> None:
        self._loaded: dict[str, BasePlugin] = {}

    def discover_all(self) -> list[BasePlugin]:
        """
        Discover plugins from all sources.

        Returns:
            List of instantiated, validated BasePlugin objects sorted by priority.
        """
        self._load_builtin_plugins()
        self._load_user_plugins()
        self._load_entry_point_plugins()

        plugins = sorted(self._loaded.values(), key=lambda p: p.priority)
        log.info(f"Plugin loader: {len(plugins)} plugin(s) discovered.")
        for p in plugins:
            log.debug(f"  [{p.name}] v{p.version} — {p.description}")
        return plugins

    def discover_by_hook(self, hook_point: str) -> list[BasePlugin]:
        """Return only plugins registered to a specific hook point."""
        all_plugins = self.discover_all()
        return [p for p in all_plugins if any(h.value == hook_point for h in p.hooks)]

    def list_available(self) -> list[dict]:
        """Return metadata about all available plugins (for CLI display)."""
        plugins = self.discover_all()
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "author": p.author,
                "hooks": [h.value for h in p.hooks],
                "enabled": p.enabled,
                "requires": p.requires,
                "available": p.is_available(),
            }
            for p in plugins
        ]

    # ------------------------------------------------------------------
    # Internal loaders
    # ------------------------------------------------------------------

    def _load_builtin_plugins(self) -> None:
        """Load plugins from src/firmxtract/plugins/builtin/."""
        builtin_dir = Path(__file__).parent.parent / "plugins" / "builtin"
        if not builtin_dir.exists():
            return
        self._load_from_directory(builtin_dir, source="builtin")

    def _load_user_plugins(self) -> None:
        """Load plugins from ~/.firmxtract/plugins/."""
        if not USER_PLUGIN_DIR.exists():
            return
        self._load_from_directory(USER_PLUGIN_DIR, source="user")

    def _load_entry_point_plugins(self) -> None:
        """Load plugins declared via entry_points in installed packages."""
        try:
            from importlib.metadata import entry_points
            eps = entry_points(group=PLUGIN_ENTRY_POINT_GROUP)
        except Exception as exc:
            log.debug(f"Entry point discovery failed: {exc}")
            return

        for ep in eps:
            try:
                cls = ep.load()
                self._register_plugin_class(cls, source=f"package:{ep.value}")
            except Exception as exc:
                log.warning(f"Failed to load entry point plugin [{ep.name}]: {exc}")

    def _load_from_directory(self, directory: Path, source: str) -> None:
        """Scan a directory for Python files containing BasePlugin subclasses."""
        for py_file in sorted(directory.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                module_name = f"firmxtract_plugin_{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BasePlugin)
                        and obj is not BasePlugin
                        and not inspect.isabstract(obj)
                    ):
                        self._register_plugin_class(obj, source=f"{source}:{py_file.name}")
            except Exception as exc:
                log.warning(f"Failed to load plugin file [{py_file.name}]: {exc}")

    def _register_plugin_class(self, cls: type, source: str) -> None:
        """Instantiate and validate a plugin class, then register it."""
        try:
            instance = cls()
            if not isinstance(instance, BasePlugin):
                return
            if instance.name in self._loaded:
                log.debug(f"Plugin [{instance.name}] already loaded — skipping [{source}]")
                return
            self._loaded[instance.name] = instance
            log.debug(f"Loaded plugin [{instance.name}] from {source}")
        except Exception as exc:
            log.warning(f"Failed to instantiate plugin [{cls.__name__}] from {source}: {exc}")
