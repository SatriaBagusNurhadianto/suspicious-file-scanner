"""Entry point for the Suspicious File Scanner app."""

from __future__ import annotations

import os
import sys

# Make src importable when running directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from suspicious_file_scanner.ui.app import run  # noqa: E402


def main() -> None:
    run()


if __name__ == "__main__":
    main()