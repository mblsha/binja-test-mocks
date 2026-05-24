"""Type stubs for binaryninja.function module."""

from typing import Any

from binaryninja.architecture import Architecture

class Function:
    """Binary Ninja Function class."""

    start: int
    name: str
    type: Any
    return_type: Any
    calling_convention: Any
    parameter_vars: list[Any]
    hlil_if_available: Any
    high_level_il: Any

    @property
    def arch(self) -> Architecture:
        """The architecture of this function."""
        ...

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
