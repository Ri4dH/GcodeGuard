"""Rule registry."""

from __future__ import annotations

from gcodeguard.rules.base import Context, Rule
from gcodeguard.rules.firmware import CalibrationTamper, PersistSettings, SdCard
from gcodeguard.rules.host import ExplicitBlock, Restart, ShellCommand, UnknownCommand
from gcodeguard.rules.motion import (
    EndstopsDisabled,
    FeedrateLimit,
    LimitsTamper,
    OutOfBounds,
    PositionOverride,
    SteppersDisabledMidPrint,
)
from gcodeguard.rules.sabotage import ExtrusionAnomaly, FlowOverride, LayerGap, TemperatureDrop
from gcodeguard.rules.thermal import (
    ColdExtrusionUnlock,
    HeaterLimit,
    LongDwellWhileHot,
    LowPrintTemperature,
)

RULE_CLASSES: tuple[type[Rule], ...] = (
    HeaterLimit,
    LongDwellWhileHot,
    ColdExtrusionUnlock,
    LowPrintTemperature,
    OutOfBounds,
    FeedrateLimit,
    LimitsTamper,
    EndstopsDisabled,
    PositionOverride,
    SteppersDisabledMidPrint,
    PersistSettings,
    CalibrationTamper,
    SdCard,
    ShellCommand,
    Restart,
    ExplicitBlock,
    UnknownCommand,
    FlowOverride,
    TemperatureDrop,
    LayerGap,
    ExtrusionAnomaly,
)

RULE_IDS = frozenset(cls.id for cls in RULE_CLASSES)


def default_rules() -> list[Rule]:
    return [cls() for cls in RULE_CLASSES]


__all__ = ["RULE_CLASSES", "RULE_IDS", "Context", "Rule", "default_rules"]
