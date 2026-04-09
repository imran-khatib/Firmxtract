"""
FirmXtract Pipeline Engine.

A generic, stage-based execution engine that replaces the hardcoded
orchestrator stages with a composable, hookable pipeline.

Design:
  - Pipeline holds ordered list of PipelineStage objects
  - Each stage wraps a BaseModule
  - Plugins registered to hook points run before/after relevant stages
  - Results collected into session after each stage
  - Any stage can be skipped, retried, or marked optional

Usage:
    pipeline = Pipeline(session)
    pipeline.add_stage(ExtractionStage(UARTHandler(session)))
    pipeline.add_stage(AnalysisStage(BinwalkWrapper(session)), optional=True)
    pipeline.register_plugin(MyPlugin())
    success = pipeline.run()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from firmxtract.core.base import BaseModule, BasePlugin, HookPoint, ModuleResult, ModuleStatus
from firmxtract.utils.logger import get_logger

if TYPE_CHECKING:
    from firmxtract.core.session import Session

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pipeline Stage
# ---------------------------------------------------------------------------


@dataclass
class PipelineStage:
    """
    A single stage in the pipeline wrapping a BaseModule.

    Attributes:
        module:   The module to execute
        optional: If True, failure does not abort the pipeline
        enabled:  If False, stage is skipped entirely
        name:     Display name (defaults to module.name)
    """
    module: BaseModule
    optional: bool = False
    enabled: bool = True
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.module.name


# ---------------------------------------------------------------------------
# Pipeline Engine
# ---------------------------------------------------------------------------


class Pipeline:
    """
    Generic stage-based execution engine.

    Stages run in order. Plugins fire at registered hook points.
    Results are accumulated in the session.

    Example:
        pipeline = Pipeline(session)
        pipeline.add_stage(PipelineStage(ExtractionModule(session)))
        pipeline.add_stage(PipelineStage(BinwalkModule(session), optional=True))
        pipeline.register_plugin(SecretsPlugin())
        success = pipeline.run()
    """

    def __init__(self, session: "Session") -> None:
        self.session = session
        self._stages: list[PipelineStage] = []
        self._plugins: list[BasePlugin] = []
        self._results: list[ModuleResult] = []

    # ------------------------------------------------------------------
    # Builder API
    # ------------------------------------------------------------------

    def add_stage(self, stage: PipelineStage) -> "Pipeline":
        """Add a stage to the pipeline. Returns self for chaining."""
        self._stages.append(stage)
        log.debug(f"Pipeline: added stage [{stage.name}]")
        return self

    def register_plugin(self, plugin: BasePlugin) -> "Pipeline":
        """Register a plugin. Plugins are sorted by priority."""
        plugin.on_load()
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: p.priority)
        log.debug(f"Pipeline: registered plugin [{plugin.name}] priority={plugin.priority}")
        return self

    def register_plugins(self, plugins: list[BasePlugin]) -> "Pipeline":
        """Register multiple plugins at once."""
        for p in plugins:
            self.register_plugin(p)
        return self

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """
        Execute all stages in order, firing plugin hooks at each stage boundary.

        Returns:
            True if all required (non-optional) stages succeeded.
        """
        log.info(
            f"[bold green]Pipeline starting — "
            f"{len(self._stages)} stage(s), "
            f"{len(self._plugins)} plugin(s)[/bold green]"
        )
        start_time = time.time()
        failed_required = False

        for i, stage in enumerate(self._stages, 1):
            if not stage.enabled:
                log.info(f"  Stage {i}/{len(self._stages)} [{stage.name}] — SKIPPED (disabled)")
                continue

            # Check module requirements
            missing = stage.module.check_requirements()
            if missing:
                msg = f"Missing required tools: {', '.join(missing)}"
                if stage.optional:
                    log.warning(f"  Stage [{stage.name}] skipped — {msg}")
                    continue
                else:
                    log.error(f"  Stage [{stage.name}] failed — {msg}")
                    self._results.append(ModuleResult(
                        module_name=stage.name,
                        status=ModuleStatus.FAILED,
                        error=msg,
                    ))
                    failed_required = True
                    break

            log.info(
                f"─── Stage {i}/{len(self._stages)}: "
                f"[bold]{stage.name}[/bold] ───────────────────────"
            )

            # Fire PRE hooks
            pre_hook = self._hook_for_stage(stage.name, pre=True)
            if pre_hook:
                self._fire_hooks(pre_hook)

            # Run the stage
            result = self._run_stage(stage)
            self._results.append(result)
            self.session.analysis_results.append(
                self._module_result_to_analysis_result(result)
            )

            # Fire POST hooks
            post_hook = self._hook_for_stage(stage.name, pre=False)
            if post_hook:
                self._fire_hooks(post_hook)

            # Handle failure
            if not result.success:
                if stage.optional:
                    log.warning(
                        f"  Stage [{stage.name}] failed (optional — continuing): "
                        f"{result.error}"
                    )
                else:
                    log.error(f"  Stage [{stage.name}] failed: {result.error}")
                    failed_required = True
                    break

        elapsed = time.time() - start_time
        status = "[red]FAILED[/red]" if failed_required else "[green]SUCCESS[/green]"
        log.info(f"Pipeline complete ({elapsed:.1f}s) — {status}")

        return not failed_required

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_stage(self, stage: PipelineStage) -> ModuleResult:
        """Run a single stage with timing and exception handling."""
        t0 = time.time()
        try:
            result = stage.module.run(self.session)
            elapsed = time.time() - t0
            icon = "[green]✓[/green]" if result.success else "[red]✗[/red]"
            log.info(f"  {icon} [{stage.name}] {elapsed:.1f}s — {result.status.value}")
            return result
        except Exception as exc:
            elapsed = time.time() - t0
            log.error(f"  [red]✗[/red] [{stage.name}] {elapsed:.1f}s — exception: {exc}",
                      exc_info=True)
            return ModuleResult(
                module_name=stage.name,
                status=ModuleStatus.FAILED,
                error=str(exc),
            )

    def _fire_hooks(self, hook_point: HookPoint) -> None:
        """Run all plugins registered to a hook point."""
        plugins = [p for p in self._plugins if hook_point in p.hooks and p.enabled]
        for plugin in plugins:
            log.debug(f"  Hook [{hook_point.value}] → plugin [{plugin.name}]")
            try:
                result = plugin.run(self.session)
                self._results.append(result)
                if not result.success:
                    log.warning(f"  Plugin [{plugin.name}] hook failed: {result.error}")
            except Exception as exc:
                log.warning(f"  Plugin [{plugin.name}] hook exception: {exc}")

    @staticmethod
    def _hook_for_stage(stage_name: str, pre: bool) -> HookPoint | None:
        """Map a stage name to its hook point."""
        mapping = {
            ("extraction", True):  HookPoint.PRE_EXTRACT,
            ("extraction", False): HookPoint.POST_EXTRACT,
            ("binwalk", True):     HookPoint.PRE_ANALYZE,
            ("binwalk", False):    HookPoint.POST_ANALYZE,
            ("secrets", True):     HookPoint.PRE_SECRETS,
            ("secrets", False):    HookPoint.POST_SECRETS,
            ("report", False):     HookPoint.POST_REPORT,
        }
        return mapping.get((stage_name.lower(), pre))

    @staticmethod
    def _module_result_to_analysis_result(result: ModuleResult) -> Any:
        """Convert ModuleResult to AnalysisResult for session compatibility."""
        from firmxtract.core.session import AnalysisResult
        return AnalysisResult(
            tool=result.module_name,
            success=result.success,
            findings=result.findings,
            error_message=result.error,
        )

    @property
    def results(self) -> list[ModuleResult]:
        """All stage and plugin results from the last run."""
        return self._results
