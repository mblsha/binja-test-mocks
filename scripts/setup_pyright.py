#!/usr/bin/env python3
"""Generate pyright configuration for Binary Ninja plugin projects."""

import json
import sys
from pathlib import Path


def generate_pyright_config(package_path: Path | None = None) -> dict:
    """Generate pyrightconfig.json content for a Binary Ninja plugin."""
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

    return {
        "include": ["src", "tests"],
        "exclude": ["**/node_modules", "**/__pycache__", "**/.*"],
        "extraPaths": [str(stubs_path)],
        "typeCheckingMode": "strict",
        "pythonVersion": "3.10",
        "pythonPlatform": "All",
        "reportMissingImports": False,
        "reportMissingTypeStubs": False,
        "reportPrivateImportUsage": False,
        "stubPath": str(stubs_path),
    }


def main() -> None:
    """Generate and print pyright configuration."""
    if len(sys.argv) > 1 and sys.argv[1] == "--save":
        config = generate_pyright_config()
        output_path = Path("pyrightconfig.json")

        if output_path.exists():
            print(f"Error: {output_path} already exists", file=sys.stderr)
            print("Remove it first or edit manually", file=sys.stderr)
            sys.exit(1)

        output_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"Created {output_path}")
    else:
        print(json.dumps(generate_pyright_config(), indent=2))
        print("\nTo save to pyrightconfig.json, run:")
        print(f"  {sys.argv[0]} --save")


if __name__ == "__main__":
    main()
