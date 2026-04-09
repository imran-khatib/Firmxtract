"""firmxtract.core package — pipeline engine, session, base classes."""

from firmxtract.core.base import (
    BaseModule,
    BasePlugin,
    HookPoint,
    ModuleResult,
    ModuleStatus,
)
from firmxtract.core.pipeline import Pipeline, PipelineStage
from firmxtract.core.plugin_loader import PluginLoader
from firmxtract.core.session import (
    AnalysisResult,
    DetectedInterface,
    ExtractionResult,
    Session,
    create_session,
)

__all__ = [
    "BaseModule",
    "BasePlugin",
    "HookPoint",
    "ModuleResult",
    "ModuleStatus",
    "Pipeline",
    "PipelineStage",
    "PluginLoader",
    "AnalysisResult",
    "DetectedInterface",
    "ExtractionResult",
    "Session",
    "create_session",
]
