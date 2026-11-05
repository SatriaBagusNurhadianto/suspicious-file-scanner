"""Tests for entropy module."""

from __future__ import annotations

from suspicious_file_scanner.core.entropy import entropy_verdict, shannon_entropy


def test_zero_entropy_for_empty():
    assert shannon_entropy(b"") == 0.0


def test_low_entropy_for_uniform():
    assert shannon_entropy(b"aaaa") == 0.0


def test_high_entropy_for_randomish():
    data = bytes(range(256)) * 4
    assert shannon_entropy(data) > 7.0


def test_verdict():
    assert "packed" in entropy_verdict(7.9)
    assert "low" in entropy_verdict(2.0).lower() or "plain" in entropy_verdict(2.0).lower()