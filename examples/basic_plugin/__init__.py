"""Example Binary Ninja plugin using binja-test-mocks for testing."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

# Add plugin directory to path
_plugin_dir = Path(__file__).resolve().parent
if str(_plugin_dir) not in sys.path:
    sys.path.insert(0, str(_plugin_dir))


def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ValueError, ImportError):
        return False


_force_mock = os.environ.get("FORCE_BINJA_MOCK", "").lower() in ("1", "true", "yes")
_skip_registration = _force_mock and not _running_inside_binary_ninja()

if not _skip_registration:
    try:
        from .example_arch import ExampleArchitecture

        ExampleArchitecture.register()
    except ImportError:
        pass
