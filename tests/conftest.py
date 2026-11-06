from __future__ import annotations

import pytest

from gcodeguard import Firewall, load_policy


@pytest.fixture
def ender3():
    return load_policy("ender3")


@pytest.fixture
def strict():
    return load_policy("ender3", "agent-strict")


@pytest.fixture
def fw(ender3):
    return Firewall(ender3)


def run(firewall: Firewall, *lines: str):
    """Feed lines through a firewall and return the decision for the last one."""
    decision = None
    for line in lines:
        decision = firewall.check(line)
    return decision


def rules_hit(decision) -> set[str]:
    return {f.rule_id for f in decision.findings}


PRINTING_PRELUDE = (
    "G28",
    "M104 S210",
    "M140 S60",
    "G90",
    "M82",
    "G92 E0",
    "G1 Z0.2 F600",
    "G1 X10 Y10 F3000",
    "G1 X100 Y10 E6",  # > 5mm extruded with a hot hotend -> printing
)
