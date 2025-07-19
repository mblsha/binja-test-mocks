#!/usr/bin/env python3
"""Run tests with Binary Ninja mocking enabled."""

import os
import subprocess
import sys


def main() -> None:
    """Run pytest with FORCE_BINJA_MOCK environment variable set."""
    # Ensure we're using mocks
    env = os.environ.copy()
    env["FORCE_BINJA_MOCK"] = "1"

    # Add any additional pytest arguments passed to this script
    pytest_args = sys.argv[1:] if len(sys.argv) > 1 else []

    # Run pytest
    cmd = [sys.executable, "-m", "pytest", *pytest_args]

    print(f"Running: {' '.join(cmd)}")
    print("With FORCE_BINJA_MOCK=1")

    result = subprocess.run(cmd, env=env)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
