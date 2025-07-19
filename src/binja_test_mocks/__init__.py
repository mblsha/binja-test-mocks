"""binja-test-mocks - Mock Binary Ninja API for testing plugins without a license."""

__version__ = "0.1.0"

# Re-export commonly used items for convenience
from . import binja_api  # noqa: F401

__all__ = ["binja_api"]