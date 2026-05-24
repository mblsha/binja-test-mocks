"""Make Binary Ninja HLIL unit-testable."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

HLIL_OPERATION_NAMES = (
    "HLIL_NOP",
    "HLIL_BLOCK",
    "HLIL_IF",
    "HLIL_WHILE",
    "HLIL_DO_WHILE",
    "HLIL_FOR",
    "HLIL_SWITCH",
    "HLIL_CASE",
    "HLIL_BREAK",
    "HLIL_CONTINUE",
    "HLIL_JUMP",
    "HLIL_RET",
    "HLIL_NORET",
    "HLIL_GOTO",
    "HLIL_LABEL",
    "HLIL_VAR_DECLARE",
    "HLIL_VAR_INIT",
    "HLIL_ASSIGN",
    "HLIL_ASSIGN_UNPACK",
    "HLIL_ASSIGN_MEM_SSA",
    "HLIL_ASSIGN_UNPACK_MEM_SSA",
    "HLIL_VAR",
    "HLIL_STRUCT_FIELD",
    "HLIL_DEREF_FIELD",
    "HLIL_ARRAY_INDEX",
    "HLIL_SPLIT",
    "HLIL_DEREF",
    "HLIL_ADDRESS_OF",
    "HLIL_CONST",
    "HLIL_CONST_PTR",
    "HLIL_CONST_DATA",
    "HLIL_IMPORT",
    "HLIL_FLOAT_CONST",
    "HLIL_EXTERN_PTR",
    "HLIL_ADD",
    "HLIL_ADC",
    "HLIL_SUB",
    "HLIL_SBB",
    "HLIL_AND",
    "HLIL_OR",
    "HLIL_XOR",
    "HLIL_LSL",
    "HLIL_LSR",
    "HLIL_ASR",
    "HLIL_ROL",
    "HLIL_RLC",
    "HLIL_ROR",
    "HLIL_RRC",
    "HLIL_MUL",
    "HLIL_MULU_DP",
    "HLIL_MULS_DP",
    "HLIL_DIVU",
    "HLIL_DIVS",
    "HLIL_DIVU_DP",
    "HLIL_DIVS_DP",
    "HLIL_MODU",
    "HLIL_MODS",
    "HLIL_MODU_DP",
    "HLIL_MODS_DP",
    "HLIL_NEG",
    "HLIL_NOT",
    "HLIL_SX",
    "HLIL_ZX",
    "HLIL_LOW_PART",
    "HLIL_BOOL_TO_INT",
    "HLIL_CMP_E",
    "HLIL_CMP_NE",
    "HLIL_CMP_SLT",
    "HLIL_CMP_ULT",
    "HLIL_CMP_SLE",
    "HLIL_CMP_ULE",
    "HLIL_CMP_SGE",
    "HLIL_CMP_UGE",
    "HLIL_CMP_SGT",
    "HLIL_CMP_UGT",
    "HLIL_FADD",
    "HLIL_FSUB",
    "HLIL_FMUL",
    "HLIL_FDIV",
    "HLIL_FSQRT",
    "HLIL_FNEG",
    "HLIL_FABS",
    "HLIL_FLOAT_TO_INT",
    "HLIL_INT_TO_FLOAT",
    "HLIL_FLOAT_CONV",
    "HLIL_ROUND_TO_INT",
    "HLIL_FLOOR",
    "HLIL_CEIL",
    "HLIL_FTRUNC",
    "HLIL_FCMP_E",
    "HLIL_FCMP_NE",
    "HLIL_FCMP_LT",
    "HLIL_FCMP_LE",
    "HLIL_FCMP_GE",
    "HLIL_FCMP_GT",
    "HLIL_FCMP_O",
    "HLIL_FCMP_UO",
    "HLIL_CALL",
    "HLIL_TAILCALL",
    "HLIL_SYSCALL",
    "HLIL_INTRINSIC",
    "HLIL_INTRINSIC_SSA",
    "HLIL_BP",
    "HLIL_TRAP",
    "HLIL_UNDEF",
    "HLIL_UNIMPL",
    "HLIL_UNIMPL_MEM",
    "HLIL_UNREACHABLE",
    "HLIL_VAR_PHI",
    "HLIL_MEM_PHI",
)


def _operation_name(op: object) -> str:
    raw = getattr(op, "name", op)
    text = str(raw).rsplit(".", 1)[-1]
    return text if text.startswith("HLIL_") else f"HLIL_{text}"


@dataclass(frozen=True)
class MockHLILStorage:
    """Small storage/source object for function parameters."""

    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class MockHLILVar:
    """Small Binary Ninja-like variable object."""

    name: str
    type: object = "uint32_t"
    source: str | None = None
    source_type: str = ""
    storage: object | None = None
    identifier: object | None = None

    def __str__(self) -> str:
        return self.name


@dataclass
class MockHighLevelILInstruction:
    """Simplified stand-in for Binary Ninja's HighLevelILInstruction."""

    op: str
    named_operands: dict[str, Any] = field(default_factory=dict)
    operand_order: list[str] = field(default_factory=list)
    operand_types: dict[str, Any] = field(default_factory=dict)
    text: str | None = None
    address: int = 0
    expr_type: object = ""
    expr_index: int = 0
    instr_index: int = 0
    function: object | None = None
    _constant: int | None = None

    def __post_init__(self) -> None:
        self.op = _operation_name(self.op)
        if not self.operand_order:
            self.operand_order = list(self.named_operands)

    @property
    def operation(self) -> Any:
        """Binary Ninja-compatible operation enum for this instruction."""
        from binaryninja.enums import HighLevelILOperation

        return getattr(HighLevelILOperation, self.op)

    @property
    def operands(self) -> list[Any]:
        """Binary Ninja-compatible positional operand list."""
        return [
            self.named_operands[name] for name in self.operand_order if name in self.named_operands
        ]

    @property
    def detailed_operands(self) -> list[tuple[str, Any, Any]]:
        """Binary Ninja-compatible named operand triples."""
        return [
            (name, self.named_operands[name], self.operand_types.get(name))
            for name in self.operand_order
            if name in self.named_operands
        ]

    @property
    def constant(self) -> int:
        """Binary Ninja-compatible constant value for constant expressions."""
        if self._constant is not None:
            return self._constant
        if "constant" in self.named_operands:
            return int(self.named_operands["constant"])
        raise AttributeError("Instruction has no constant")

    def __getattr__(self, name: str) -> Any:
        if name in self.named_operands:
            return self.named_operands[name]
        raise AttributeError(name)

    def __str__(self) -> str:
        if self.text is not None:
            return self.text
        if self.op in {"HLIL_CONST", "HLIL_CONST_PTR"}:
            return str(self.constant)
        if self.op == "HLIL_VAR":
            return str(self.named_operands.get("var", ""))
        if self.op == "HLIL_IMPORT":
            return str(self.named_operands.get("name", self.named_operands.get("dest", "")))
        if self.op in {"HLIL_ASSIGN", "HLIL_VAR_INIT"}:
            return f"{self.named_operands.get('dest', self.named_operands.get('var', ''))} = {self.named_operands.get('src', '')}"
        if self.op == "HLIL_CALL":
            params = self.named_operands.get("params", [])
            params_text = ", ".join(str(param) for param in _iterable(params))
            return f"{self.named_operands.get('dest', '')}({params_text})"
        if self.op == "HLIL_RET":
            src = self.named_operands.get("src", [])
            if not src:
                return "return"
            return "return " + ", ".join(str(item) for item in _iterable(src))
        values = ", ".join(str(value) for value in self.operands)
        return f"{self.op}({values})" if values else self.op


def _iterable(value: object) -> Iterable[object]:
    if isinstance(value, list | tuple):
        return value
    return (value,)


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
) -> MockHighLevelILInstruction:
    """Create a single mock HLIL instruction."""
    operands = dict(named_operands or {})
    return MockHighLevelILInstruction(
        op=_operation_name(op),
        named_operands=operands,
        operand_order=list(operand_order or operands),
        operand_types=dict(operand_types or {}),
        text=text,
        address=address,
        expr_type=expr_type,
        _constant=constant,
    )


class MockHighLevelILFunction:
    """Minimal high-level IL function with helpers for building tests."""

    def __init__(
        self,
        instructions: Sequence[MockHighLevelILInstruction] | None = None,
        *,
        current_address: int = 0,
    ) -> None:
        self.instructions: list[MockHighLevelILInstruction] = []
        self.current_address = current_address
        for instruction in instructions or ():
            self.append(instruction)

    def __iter__(self) -> Iterable[MockHighLevelILInstruction]:
        return iter(self.instructions)

    def __len__(self) -> int:
        return len(self.instructions)

    def __getitem__(self, index: int) -> MockHighLevelILInstruction:
        return self.instructions[index]

    def append(self, instruction: MockHighLevelILInstruction) -> int:
        index = len(self.instructions)
        instruction.function = self
        instruction.instr_index = index
        if instruction.expr_index == 0:
            instruction.expr_index = index
        self.instructions.append(instruction)
        return index

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
    ) -> MockHighLevelILInstruction:
        return mhlil(
            op,
            named_operands,
            text=text,
            address=self.current_address if address is None else address,
            expr_type=expr_type,
            constant=constant,
            operand_order=operand_order,
            operand_types=operand_types,
        )

    def const(
        self,
        value: int,
        *,
        expr_type: object = "int32_t",
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_CONST",
            {"constant": value},
            text=str(value),
            address=address,
            expr_type=expr_type,
            constant=value,
        )

    def const_pointer(
        self,
        value: int,
        *,
        expr_type: object = "void *",
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_CONST_PTR",
            {"constant": value},
            text=hex(value),
            address=address,
            expr_type=expr_type,
            constant=value,
        )

    def import_expr(
        self,
        name: str,
        *,
        address: int | None = None,
        expr_type: object = "",
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_IMPORT",
            {"name": name},
            text=name,
            address=address,
            expr_type=expr_type,
        )

    def var(
        self,
        var: MockHLILVar | str,
        *,
        expr_type: object = "uint32_t",
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        variable = MockHLILVar(var) if isinstance(var, str) else var
        return self.expr(
            "HLIL_VAR",
            {"var": variable},
            text=str(variable),
            address=address,
            expr_type=expr_type,
        )

    def var_declare(
        self,
        var: MockHLILVar | str,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        variable = MockHLILVar(var) if isinstance(var, str) else var
        return self.expr(
            "HLIL_VAR_DECLARE",
            {"var": variable},
            text=f"{variable};",
            address=address,
            expr_type=getattr(variable, "type", ""),
        )

    def var_init(
        self,
        var: MockHLILVar | str,
        src: object,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        variable = MockHLILVar(var) if isinstance(var, str) else var
        return self.expr(
            "HLIL_VAR_INIT",
            {"var": variable, "src": src},
            text=f"{variable} = {src}",
            address=address,
            expr_type=getattr(variable, "type", ""),
            operand_order=("var", "src"),
        )

    def assign(
        self,
        dest: object,
        src: object,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_ASSIGN",
            {"dest": dest, "src": src},
            text=f"{dest} = {src}",
            address=address,
            operand_order=("dest", "src"),
        )

    def ret(
        self,
        src: Sequence[object] | object | None = None,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        src_items = [] if src is None else list(src) if isinstance(src, list | tuple) else [src]
        return self.expr("HLIL_RET", {"src": src_items}, address=address)

    def call(
        self,
        dest: object,
        params: Sequence[object] | None = None,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        params_list = list(params or [])
        return self.expr(
            "HLIL_CALL",
            {"dest": dest, "params": params_list},
            address=address,
            expr_type=expr_type,
            operand_order=("dest", "params"),
        )

    def unary(
        self,
        op: object,
        src: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr(op, {"src": src}, address=address, expr_type=expr_type)

    def binary(
        self,
        op: object,
        left: object,
        right: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr(
            op,
            {"left": left, "right": right},
            address=address,
            expr_type=expr_type,
            operand_order=("left", "right"),
        )

    def deref(
        self,
        src: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr("HLIL_DEREF", {"src": src}, address=address, expr_type=expr_type)

    def deref_field(
        self,
        src: object,
        offset: int,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_DEREF_FIELD",
            {"src": src, "offset": offset},
            address=address,
            expr_type=expr_type,
            operand_order=("src", "offset"),
        )

    def struct_field(
        self,
        src: object,
        offset: int,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_STRUCT_FIELD",
            {"src": src, "offset": offset},
            address=address,
            expr_type=expr_type,
            operand_order=("src", "offset"),
        )

    def array_index(
        self,
        src: object,
        index: object,
        *,
        address: int | None = None,
        expr_type: object = "uint32_t",
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_ARRAY_INDEX",
            {"src": src, "index": index},
            address=address,
            expr_type=expr_type,
            operand_order=("src", "index"),
        )

    def block(
        self,
        body: Sequence[object],
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr("HLIL_BLOCK", {"body": list(body)}, address=address)

    def if_expr(
        self,
        condition: object,
        true: object,
        false: object | None = None,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        operands: dict[str, Any] = {"condition": condition, "true": true}
        if false is not None:
            operands["false"] = false
        return self.expr(
            "HLIL_IF",
            operands,
            address=address,
            operand_order=("condition", "true", "false"),
        )

    def while_expr(
        self,
        condition: object,
        body: object,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_WHILE",
            {"condition": condition, "body": body},
            address=address,
            operand_order=("condition", "body"),
        )

    def do_while(
        self,
        body: object,
        condition: object,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_DO_WHILE",
            {"body": body, "condition": condition},
            address=address,
            operand_order=("body", "condition"),
        )

    def switch(
        self,
        condition: object,
        cases: Sequence[object],
        default: object | None = None,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        operands: dict[str, Any] = {"condition": condition, "cases": list(cases)}
        if default is not None:
            operands["default"] = default
        return self.expr(
            "HLIL_SWITCH",
            operands,
            address=address,
            operand_order=("condition", "cases", "default"),
        )

    def case(
        self,
        values: Sequence[object],
        body: object,
        *,
        address: int | None = None,
    ) -> MockHighLevelILInstruction:
        return self.expr(
            "HLIL_CASE",
            {"values": list(values), "body": body},
            address=address,
            operand_order=("values", "body"),
        )

    def nop(self, *, address: int | None = None) -> MockHighLevelILInstruction:
        return self.expr("HLIL_NOP", {}, address=address)

    def break_expr(self, *, address: int | None = None) -> MockHighLevelILInstruction:
        return self.expr("HLIL_BREAK", {}, address=address)

    def continue_expr(self, *, address: int | None = None) -> MockHighLevelILInstruction:
        return self.expr("HLIL_CONTINUE", {}, address=address)
