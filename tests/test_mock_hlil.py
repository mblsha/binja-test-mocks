"""Regression tests for mock HLIL helpers."""

from __future__ import annotations

import importlib
import os
from typing import Any

import pytest

os.environ["FORCE_BINJA_MOCK"] = "1"


def _walk_hlil_ops(root: Any) -> set[str]:
    nodes = list(getattr(root, "instructions", []) or [])
    ops: set[str] = set()
    while nodes:
        node = nodes.pop()
        ops.add(str(node.operation).rsplit(".", 1)[-1])
        for child in getattr(node, "operands", []) or []:
            if hasattr(child, "operation"):
                nodes.append(child)
            elif isinstance(child, list | tuple):
                nodes.extend(item for item in child if hasattr(item, "operation"))
    return ops


def test_mock_hlil_instruction_surface() -> None:
    importlib.import_module("binja_test_mocks.binja_api")

    from binaryninja.enums import HighLevelILOperation

    from binja_test_mocks.mock_hlil import MockHighLevelILFunction, MockHLILVar

    il = MockHighLevelILFunction(current_address=0x401000)
    var = MockHLILVar("result", type="uint32_t")
    one = il.const(1)
    two = il.const(2)
    add = il.binary(HighLevelILOperation.HLIL_ADD, one, two)
    init = il.var_init(var, add)

    assert add.operation == HighLevelILOperation.HLIL_ADD
    assert add.operands == [one, two]
    assert [name for name, _value, _operand_type in add.detailed_operands] == ["left", "right"]
    assert add.address == 0x401000
    assert one.constant == 1
    assert two.constant == 2
    assert init.var == var
    assert init.src is add

    with pytest.raises(AttributeError):
        _ = add.constant


def test_mock_hlil_function_metadata_and_nested_operands() -> None:
    importlib.import_module("binja_test_mocks.binja_api")

    from binaryninja.function import Function

    from binja_test_mocks.mock_hlil import (
        MockHighLevelILFunction,
        MockHLILStorage,
        MockHLILVar,
    )

    il = MockHighLevelILFunction(current_address=0x401020)
    result = MockHLILVar("result", type="uint32_t", source="eax", storage=MockHLILStorage("eax"))
    time_get_time = il.import_expr("timeGetTime")
    call = il.call(time_get_time, [])
    il.append(il.var_init(result, call))
    il.append(il.ret([il.var(result)]))

    func = Function(
        start=0x401020,
        name="read_tick",
        return_type="uint32_t",
        type="uint32_t read_tick()",
        high_level_il=il,
        parameter_vars=[result],
    )

    assert func.start == 0x401020
    assert func.name == "read_tick"
    assert func.hlil_if_available is il
    assert func.high_level_il is il
    assert len(func.parameter_vars) == 1
    assert str(time_get_time) == "timeGetTime"
    assert _walk_hlil_ops(il) == {
        "HLIL_CALL",
        "HLIL_IMPORT",
        "HLIL_RET",
        "HLIL_VAR",
        "HLIL_VAR_INIT",
    }
