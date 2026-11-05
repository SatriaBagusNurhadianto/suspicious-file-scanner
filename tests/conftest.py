"""Shared test fixtures."""

from __future__ import annotations

import pytest

from suspicious_file_scanner.core.contracts import SafetyLimits


@pytest.fixture
def limits() -> SafetyLimits:
    return SafetyLimits(max_file_size=1024 * 1024)


@pytest.fixture
def strict_limits() -> SafetyLimits:
    return SafetyLimits(max_file_size=1024 * 1024, strict_mode=True)
