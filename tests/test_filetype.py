"""Tests for filetype detection."""

from __future__ import annotations

import tempfile
from pathlib import Path

from suspicious_file_scanner.core.filetype import detect_file_type


def test_pe_detection():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ" + b"\x00" * 62)
        path = f.name
    try:
        assert detect_file_type(path).startswith("PE")
    finally:
        Path(path).unlink()


def test_elf_detection():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        path = f.name
    try:
        assert detect_file_type(path).startswith("ELF")
    finally:
        Path(path).unlink()