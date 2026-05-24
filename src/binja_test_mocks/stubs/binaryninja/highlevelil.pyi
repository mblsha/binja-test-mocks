# ruff: noqa: A002

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

HighLevelILOperation: Any

class MockHLILStorage:
    name: str
    def __init__(self, name: str) -> None: ...
    def __str__(self) -> str: ...

class MockHLILVar:
    name: str
    type: object
    source: str | None
    source_type: str
    storage: object | None
    identifier: object | None
    def __init__(
        self,
        name: str,
        type: object = "uint32_t",
        source: str | None = None,
        source_type: str = "",
        storage: object | None = None,
        identifier: object | None = None,
    ) -> None: ...
    def __str__(self) -> str: ...

class HighLevelILInstruction:
    op: str
    named_operands: dict[str, Any]
    operand_order: list[str]
    operand_types: dict[str, Any]
    text: str | None
    address: int
    expr_type: object
    expr_index: int
    instr_index: int
    function: object | None
    @property
    def operation(self) -> Any: ...
    @property
    def operands(self) -> list[Any]: ...
    @property
    def detailed_operands(self) -> list[tuple[str, Any, Any]]: ...
    @property
    def constant(self) -> int: ...

class HighLevelILFunction:
    instructions: list[HighLevelILInstruction]
    current_address: int
    def __init__(
        self,
        instructions: Sequence[HighLevelILInstruction] | None = None,
        *,
        current_address: int = 0,
    ) -> None: ...
    def __iter__(self) -> Iterable[HighLevelILInstruction]: ...
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> HighLevelILInstruction: ...
    def append(self, instruction: HighLevelILInstruction) -> int: ...
    def expr(
        self,
        op: object,
        named_operands: Mapping[str, Any] | None = None,
        *,
        text: str | None = None,
        address: int | None = None,
        expr_type: object = "",
        constant: int | None = None,
        operand_order: Sequence[str] | None = None,
        operand_types: Mapping[str, Any] | None = None,
    ) -> HighLevelILInstruction: ...
    def const(
        self, value: int, *, expr_type: object = "int32_t", address: int | None = None
    ) -> HighLevelILInstruction: ...
    def const_pointer(
        self, value: int, *, expr_type: object = "void *", address: int | None = None
    ) -> HighLevelILInstruction: ...
    def import_expr(
        self, name: str, *, address: int | None = None, expr_type: object = ""
    ) -> HighLevelILInstruction: ...
    def var(
        self, var: MockHLILVar | str, *, expr_type: object = "uint32_t", address: int | None = None
    ) -> HighLevelILInstruction: ...
    def var_declare(
        self, var: MockHLILVar | str, *, address: int | None = None
    ) -> HighLevelILInstruction: ...
    def var_init(
        self, var: MockHLILVar | str, src: object, *, address: int | None = None
    ) -> HighLevelILInstruction: ...
    def assign(
        self, dest: object, src: object, *, address: int | None = None
    ) -> HighLevelILInstruction: ...
    def ret(
        self, src: Sequence[object] | object | None = None, *, address: int | None = None
    ) -> HighLevelILInstruction: ...
    def call(
        self,
        dest: object,
        params: Sequence[object] | None = None,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> HighLevelILInstruction: ...
    def unary(
        self,
        op: object,
        src: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> HighLevelILInstruction: ...
    def binary(
        self,
        op: object,
        left: object,
        right: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> HighLevelILInstruction: ...

MockHighLevelILInstruction = HighLevelILInstruction
MockHighLevelILFunction = HighLevelILFunction

def mhlil(
    op: object,
    named_operands: Mapping[str, Any] | None = None,
    *,
    text: str | None = None,
    address: int = 0,
    expr_type: object = "",
    constant: int | None = None,
    operand_order: Sequence[str] | None = None,
    operand_types: Mapping[str, Any] | None = None,
) -> HighLevelILInstruction: ...
