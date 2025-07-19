"""Module entry point for test runner."""

import sys
from pathlib import Path

# Add the scripts directory to the path
scripts_dir = Path(__file__).parent.parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from run_tests import main  # type: ignore[import-not-found]

if __name__ == "__main__":
    main()
