#!/usr/bin/env python3
"""Generate mypy configuration for Binary Ninja plugin projects."""

import sys
from pathlib import Path


def generate_mypy_config(package_path: Path | None = None) -> str:
    """Generate mypy.ini content for a Binary Ninja plugin."""
    if package_path is None:
        # Try to find binja-test-mocks installation
        try:
            import binja_test_mocks

            package_path = Path(binja_test_mocks.__file__).parent
        except ImportError:
            print("Error: binja-test-mocks is not installed", file=sys.stderr)
            print("Install it with: pip install binja-test-mocks", file=sys.stderr)
            sys.exit(1)

    stubs_path = package_path / "stubs"

    return f"""[mypy]
mypy_path = {stubs_path}
python_version = 3.10
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
check_untyped_defs = True
strict_optional = True

[mypy-binaryninja.*]
ignore_missing_imports = False

[mypy-binja_test_mocks.*]
ignore_missing_imports = False

# Add your plugin-specific configurations below
"""


def main() -> None:
    """Generate and print mypy configuration."""
    if len(sys.argv) > 1 and sys.argv[1] == "--save":
        config = generate_mypy_config()
        output_path = Path("mypy.ini")

        if output_path.exists():
            print(f"Error: {output_path} already exists", file=sys.stderr)
            print("Remove it first or edit manually", file=sys.stderr)
            sys.exit(1)

        output_path.write_text(config)
        print(f"Created {output_path}")
    else:
        print(generate_mypy_config())
        print("\nTo save to mypy.ini, run:")
        print(f"  {sys.argv[0]} --save")


if __name__ == "__main__":
    main()
