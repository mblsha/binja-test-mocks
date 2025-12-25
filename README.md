# binja-test-mocks

[![CI](https://github.com/mblsha/binja-test-mocks/actions/workflows/tests.yml/badge.svg)](https://github.com/mblsha/binja-test-mocks/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/binja-test-mocks.svg)](https://badge.fury.io/py/binja-test-mocks)
[![Python versions](https://img.shields.io/pypi/pyversions/binja-test-mocks.svg)](https://pypi.org/project/binja-test-mocks/)

Mock Binary Ninja API for testing Binary Ninja plugins without requiring a Binary Ninja license.

## Overview

`binja-test-mocks` provides a comprehensive set of mock objects and utilities that allow you to:
- Unit test Binary Ninja plugins without a Binary Ninja installation
- Run type checking with mypy/pyright using accurate type stubs
- Develop and test plugins in CI/CD environments

## Installation

```bash
pip install binja-test-mocks
```

With `uv`:
```bash
uv add --dev binja-test-mocks pytest
```

For development:
```bash
pip install -e /path/to/binja-test-mocks
```

## Quick Start

### Recommended pytest setup (mocks only in tests/CI)

```python
# tests/conftest.py
#
# Import binja-test-mocks *before* importing anything that does `import binaryninja`.
# This keeps mocks scoped to unit tests/CI and avoids impacting real Binary Ninja.
from __future__ import annotations

import importlib.util
import os

def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ValueError, ImportError):
        return False

if not _running_inside_binary_ninja():
    os.environ.setdefault("FORCE_BINJA_MOCK", "1")

    # Installs a stubbed `binaryninja` module into `sys.modules`.
    from binja_test_mocks import binja_api  # noqa: F401

    # Optional but common: configure architecture-specific IL size suffixes.
    from binja_test_mocks import mock_llil

    mock_llil.set_size_lookup(
        {1: ".b", 2: ".w", 4: ".d", 8: ".q", 16: ".o"},
        {"b": 1, "w": 2, "d": 4, "q": 8, "o": 16},
    )
```

### Example: lift bytes to LLIL

```python
from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockLabel, MockLLIL, mllil

from your_plugin.arch import MyArchitecture

def lift_all(data: bytes, *, start_addr: int = 0) -> list[MockLLIL]:
    arch = MyArchitecture()
    il = lowlevelil.LowLevelILFunction(arch)

    offset = 0
    while offset < len(data):
        il.current_address = start_addr + offset  # type: ignore[attr-defined]
        length = arch.get_instruction_low_level_il(data[offset:], start_addr + offset, il)
        assert length is not None and length > 0
        offset += length

    # Mock LLIL emits LABEL pseudo-nodes for control-flow; ignore them.
    return [node for node in il if not isinstance(node, MockLabel)]

def test_instruction_lifting() -> None:
    assert lift_all(b"\x90") == [mllil("NOP")]
```

## Safe Integration Guide (Binary Ninja plugins)

### Keep mocks scoped to tests/CI

- Put the `binja_test_mocks.binja_api` import in `tests/conftest.py` (not in your plugin package).
- Set `FORCE_BINJA_MOCK=1` only for test runs (CI job env, `pytest`, etc.).
- Keep `binja-test-mocks` in dev/test dependencies (don’t require it at runtime in Binary Ninja).

`binja_test_mocks.binja_api` is defensive: even if `FORCE_BINJA_MOCK=1` is set globally, it will
refuse to install mocks when it detects it’s running inside the Binary Ninja application process
(unless you explicitly set `ALLOW_BINJA_MOCK_IN_BINARY_NINJA=1`).

### Avoid registration side effects during tests

If your plugin registers architectures/commands at import time, tests that import your package may
accidentally run that registration code. A robust pattern is:

- `your_plugin/_bn_plugin.py`: define `register()` (calls `Architecture.register()`, `PluginCommand.register_*()`, etc.)
- `your_plugin/__init__.py`: call `register()` only when running inside Binary Ninja (and not under `FORCE_BINJA_MOCK`)

This is the same approach used by `mblsha/binaryninja-m68k` (see
[`mblsha/binaryninja-m68k#1`](https://github.com/mblsha/binaryninja-m68k/pull/1)).

### Write tests against bytes (disasm + LLIL)

- Disassembly: `arch.get_instruction_text(data, addr)` → join token `.text` → compare to expected string.
- LLIL: `arch.get_instruction_low_level_il(...)` into a `LowLevelILFunction` → compare the resulting `MockLLIL` tree.
- Control flow: the mock IL may include `MockLabel` nodes; filter or assert them as needed.

If your plugin needs more `binaryninja.*` surface than is currently mocked, prefer adding it here
(via PR) instead of copy/pasting ad-hoc stubs into each plugin repository.

## Components

### Mock Modules

- **binja_api.py**: Core mock loader that intercepts Binary Ninja imports
- **mock_llil.py**: Mock Low Level IL classes and operations
- **mock_binaryview.py**: Mock BinaryView for testing file format plugins
- **mock_analysis.py**: Mock analysis information (branches, calls, etc.)
- **tokens.py**: Token generation utilities for disassembly
- **coding.py**: Binary encoding/decoding helpers
- **eval_llil.py**: LLIL expression evaluator for testing

### Type Stubs

Complete type stubs for Binary Ninja API in `stubs/binaryninja/`:
- architecture.pyi
- binaryview.pyi
- lowlevelil.pyi
- enums.pyi
- types.pyi
- function.pyi
- log.pyi
- interaction.pyi

## Integration Examples

### Plugin entrypoint pattern (safe with tests)

```python
# your_plugin/__init__.py
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

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
    # Keep registration in a separate module to avoid side effects in unit tests.
    from ._bn_plugin import register

    register(plugin_dir=_plugin_dir)
```

### Type Checking Configuration

#### mypy.ini
```ini
[mypy]
mypy_path = /path/to/binja-test-mocks/src/binja_test_mocks/stubs
plugins = mypy_binja_plugin

[mypy-binaryninja.*]
ignore_missing_imports = False
```

#### pyrightconfig.json
```json
{
  "extraPaths": [
    "/path/to/binja-test-mocks/src/binja_test_mocks/stubs"
  ],
  "typeCheckingMode": "strict"
}
```

### Running Tests

```bash
# Typical (with `tests/conftest.py` setting `FORCE_BINJA_MOCK`)
pytest

# With uv
uv run pytest

# Belt-and-suspenders: force mocks even if you don't have a conftest
FORCE_BINJA_MOCK=1 uv run pytest

# Bundled runner (same as running pytest under the hood)
binja-test-runner
```

## Advanced Usage

### Custom Mock Behavior

```python
from binja_test_mocks.mock_llil import MockLowLevelILFunction

class CustomMockIL(MockLowLevelILFunction):
    def __init__(self):
        super().__init__()
        self.custom_data = []
    
    def append(self, expr):
        self.custom_data.append(expr)
        return super().append(expr)
```

### Testing Binary Views

```python
from binja_test_mocks.mock_binaryview import MockBinaryView

def test_binary_view_parsing():
    data = b"\x4d\x5a\x90\x00"  # PE header
    bv = MockBinaryView(data)
    
    # Your binary view implementation
    my_view = MyBinaryView(bv)
    assert my_view.init()
```

## Migration from binja_helpers

If you're migrating from the old `binja_helpers`:

1. Update imports:
   ```python
   # Old
   from binja_helpers import binja_api
   
   # New
   from binja_test_mocks import binja_api
   ```

2. Update path additions if needed:
   ```python
   # Old
   sys.path.insert(0, str(plugin_dir / "binja_helpers_tmp"))
   
   # New - not needed if installed via pip
   ```

## Contributing

Contributions are welcome! Please ensure:
- All tests pass with `pytest`
- Type checking passes with `mypy` and `pyright`
- Code is formatted with `ruff`

## License

MIT License - see LICENSE file for details.
