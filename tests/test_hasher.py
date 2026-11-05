"""Tests for hasher module."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from suspicious_file_scanner.core.hasher import compute_hashes


def test_compute_hashes_known_content():
    content = b"hello world"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        path = f.name
    try:
        result = compute_hashes(path)
        assert result["md5"] == hashlib.md5(content).hexdigest()  # noqa: S324
        assert result["sha1"] == hashlib.sha1(content).hexdigest()  # noqa: S324
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
    finally:
        Path(path).unlink()