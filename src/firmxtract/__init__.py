"""FirmXtract — Unified IoT Firmware Extraction, Analysis, and Red-Teaming Framework."""

__version__ = "0.1.0"
__author__ = "FirmXtract Project"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "get_version"]


def get_version() -> str:
    """Return the package version string.

    Preferred over importing __version__ directly — allows future
    dynamic version resolution (importlib.metadata) without changing call sites.

    Returns:
        Version string, e.g. "0.1.0".
    """
    return __version__
