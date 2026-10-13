from __future__ import annotations

from scripts.attack_emulator import run_emulation


def test_attack_emulator_passes():
    summary = run_emulation()
    assert summary["failed"] == []
    assert summary["detection_proxy"] == 1.0
