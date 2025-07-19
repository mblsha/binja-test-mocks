# Migration Guide: From binja_helpers to binja-test-mocks

This guide helps you migrate existing Binary Ninja plugins from using the old `binja_helpers` module to the new `binja-test-mocks` package.

## Quick Migration Steps

### 1. Install binja-test-mocks

```bash
pip install binja-test-mocks
```

Or for development:
```bash
pip install -e /path/to/binja-test-mocks
```

### 2. Update Imports

Replace all imports of `binja_helpers` with `binja_test_mocks`:

#### Old:
```python
from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction
from binja_helpers.tokens import TInt, TText
```

#### New:
```python
from binja_test_mocks import binja_api  # noqa: F401
from binja_test_mocks.mock_llil import MockLowLevelILFunction
from binja_test_mocks.tokens import TInt, TText
```

### 3. Remove Path Manipulation

If your plugin adds `binja_helpers` to `sys.path`, remove that code:

#### Remove this:
```python
# Add the vendored binja_helpers directory to sys.path
_helpers_dir = _plugin_dir / "binja_helpers_tmp"
if _helpers_dir.is_dir() and str(_helpers_dir) not in sys.path:
    sys.path.insert(0, str(_helpers_dir))
```

### 4. Update .gitignore

Add binja-test-mocks to your `.gitignore` if using a local development install:

```
binja-test-mocks/
```

### 5. Update Test Files

Update all test files that use binja_helpers:

```python
# Old
import os
os.environ["FORCE_BINJA_MOCK"] = "1"
from binja_helpers import binja_api  # noqa: F401

# New
import os
os.environ["FORCE_BINJA_MOCK"] = "1"
from binja_test_mocks import binja_api  # noqa: F401
```

### 6. Update Type Checking Configuration

#### mypy.ini
```ini
[mypy]
# Use the setup script to generate proper paths
# python -m binja_test_mocks.scripts.setup_mypy --save
```

#### pyrightconfig.json
```json
{
  // Use the setup script to generate proper config
  // python -m binja_test_mocks.scripts.setup_pyright --save
}
```

## API Changes

### MockLowLevelILFunction

The `MockLowLevelILFunction` attribute for stored operations has changed:

#### Old:
```python
il.operations  # This doesn't exist
```

#### New:
```python
il.ils  # List of MockLLIL operations
```

### Size Lookup Configuration

For architectures with custom word sizes:

```python
from binja_test_mocks.mock_llil import set_size_lookup

# Configure for 32-bit architecture
set_size_lookup(
    size_lookup={1: ".b", 2: ".w", 4: ".4"},
    suffix_sz={"b": 1, "w": 2, "4": 4}
)
```

## Complete Example Migration

### Before (using binja_helpers as submodule):

**__init__.py:**
```python
from pathlib import Path
import sys

_plugin_dir = Path(__file__).resolve().parent
if str(_plugin_dir) not in sys.path:
    sys.path.insert(0, str(_plugin_dir))

_helpers_dir = _plugin_dir / "binja_helpers_tmp"
if _helpers_dir.is_dir() and str(_helpers_dir) not in sys.path:
    sys.path.insert(0, str(_helpers_dir))

from binja_helpers import binja_api  # noqa: F401

# Rest of plugin code...
```

**test_plugin.py:**
```python
import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_helpers import binja_api  # noqa: F401
from binja_helpers.mock_llil import MockLowLevelILFunction
```

### After (using binja-test-mocks):

**__init__.py:**
```python
import os
from pathlib import Path
import sys

_plugin_dir = Path(__file__).resolve().parent
if str(_plugin_dir) not in sys.path:
    sys.path.insert(0, str(_plugin_dir))

# For testing, load mock API
if os.environ.get("FORCE_BINJA_MOCK") == "1":
    from binja_test_mocks import binja_api  # noqa: F401

# Rest of plugin code...
```

**test_plugin.py:**
```python
import os
os.environ["FORCE_BINJA_MOCK"] = "1"

from binja_test_mocks import binja_api  # noqa: F401
from binja_test_mocks.mock_llil import MockLowLevelILFunction
```

**requirements.txt** or **pyproject.toml:**
```
binja-test-mocks>=0.1.0
```

## Removing the Submodule

If you were using binja_helpers as a git submodule:

```bash
# Remove the submodule
git submodule deinit binja_helpers_tmp
git rm binja_helpers_tmp
rm -rf .git/modules/binja_helpers_tmp

# Commit the changes
git commit -m "Remove binja_helpers submodule, switch to binja-test-mocks"
```

## Benefits of Migration

1. **Easier Installation**: Simple `pip install` instead of git submodules
2. **Version Management**: Pin specific versions in requirements.txt
3. **Cleaner Repository**: No submodule complexity
4. **Shared Maintenance**: Bug fixes and improvements benefit all users
5. **Type Checking**: Integrated type stubs work out of the box

## Troubleshooting

### Import Errors

If you get import errors after migration:
1. Ensure binja-test-mocks is installed: `pip list | grep binja-test-mocks`
2. Check that FORCE_BINJA_MOCK is set before imports
3. Verify all imports have been updated

### Type Checking Issues

If mypy/pyright can't find Binary Ninja types:
1. Run the setup scripts to generate proper configs
2. Ensure your virtual environment has binja-test-mocks installed
3. Check that stub paths are correctly configured

### Test Failures

If tests fail after migration:
1. Update `il.operations` to `il.ils`
2. Configure size lookup for custom architectures
3. Check for any custom modifications to binja_helpers that need porting

## Need Help?

If you encounter issues during migration:
1. Check the [examples/](examples/) directory for working examples
2. File an issue at https://github.com/mblsha/binja-test-mocks/issues
3. Include your old binja_helpers usage for specific migration advice