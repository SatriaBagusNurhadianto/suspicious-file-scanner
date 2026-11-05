"""Tests for risk scoring."""

from __future__ import annotations

from suspicious_file_scanner.core.risk_score import compute_risk


def test_low_risk_plain():
    r = compute_risk("text/plain", 2.0, [], [], ".txt")
    assert r.level == "low"
    assert r.score < 20


def test_high_risk_packed_pe():
    r = compute_risk("PE (Windows executable)", 7.9, ["kernel32.dll!VirtualAlloc"], ["http://evil.example"], ".exe")
    assert r.score >= 45
    assert r.level in ("high", "critical")