"""Sabotage rules: subtle changes that weaken parts without looking dangerous.

These are heuristics. They raise warnings by default rather than blocking,
because legitimate prints (temperature towers, variable layer height, gap fill)
can look similar. See docs/rules.md for the false-positive discussion.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Iterable

from gcodeguard.model import Category, Finding, Severity
from gcodeguard.policy import Policy
from gcodeguard.rules.base import Context, Rule, fmt
from gcodeguard.state import MachineState

_MIN_SEGMENT_MM = 0.5
_LAYER_HISTORY = 12


class FlowOverride(Rule):
    id = "sabotage.flow_override"
    category = Category.SABOTAGE
    severity = Severity.WARNING
    summary = "Flow (M221) or speed (M220) override outside the expected range."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd, sab = ctx.cmd, ctx.policy.sabotage
        value = cmd.num("S")
        if value is None or cmd.code not in {"M220", "M221"}:
            return
        bounds = sab.flow_percent if cmd.code == "M221" else sab.speed_percent
        if bounds.contains(value):
            return
        what = "flow" if cmd.code == "M221" else "speed"
        severity = Severity.CRITICAL if ctx.state.is_printing and cmd.code == "M221" else None
        yield self.hit(
            ctx,
            f"{cmd.code} sets {what} to {fmt(value)}% (expected {fmt(bounds.low)}-"
            f"{fmt(bounds.high)}%){' mid-print' if ctx.state.is_printing else ''}",
            severity=severity,
        )


class TemperatureDrop(Rule):
    id = "sabotage.temperature_drop"
    category = Category.SABOTAGE
    severity = Severity.WARNING
    summary = "Hotend temperature dropped sharply mid-print (weak layer bonding)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        state = ctx.state
        if not state.is_printing or state.print_temp is None:
            return
        from gcodeguard.commands import heater_targets

        for heater in heater_targets(ctx.cmd, state.active_tool):
            if heater.heater != "hotend" or heater.target <= 0 or heater.index != state.active_tool:
                continue
            drop = state.print_temp - heater.target
            if drop > ctx.policy.thermal.max_temp_drop_c:
                yield self.hit(
                    ctx,
                    f"hotend drops {fmt(drop)}C mid-print ({fmt(state.print_temp)} -> "
                    f"{fmt(heater.target)}C): layers printed now bond poorly",
                )


class LayerGap(Rule):
    id = "sabotage.layer_gap"
    category = Category.SABOTAGE
    severity = Severity.WARNING
    summary = "Z jumps further than one layer between extrusions (void layer / delamination)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        motion, state = ctx.motion, ctx.state
        if motion is None or not state.is_printing or state.last_extrude_z is None:
            return
        if motion.e_delta <= 0 or motion.distance_xy < _MIN_SEGMENT_MM:
            return
        gap = motion.physical["Z"] - state.last_extrude_z
        limit = ctx.policy.machine.max_layer_height_mm * 1.5
        if gap > limit:
            yield self.hit(
                ctx,
                f"extrusion resumes {fmt(round(gap, 3))}mm above the previous layer "
                f"(max layer height {fmt(ctx.policy.machine.max_layer_height_mm)}mm): "
                "a layer is missing",
            )


class ExtrusionAnomaly(Rule):
    """Compares each layer's extrusion-per-mm with the print's own history and with physics.

    Moves extruding under ``_FAINT`` x baseline are treated as ironing/coasting
    (legitimate low-flow passes): they are left out of the layer median and the
    run counter. A layer made *only* of such moves is still flagged, so a
    near-zero-flow layer can't hide behind the ironing exemption. The final layer
    is exempt from the relative check (vase-mode and top-surface tapers).
    """

    id = "sabotage.extrusion_anomaly"
    category = Category.SABOTAGE
    severity = Severity.WARNING
    summary = "Extrusion per mm deviates from the print's baseline (under/over-extrusion)."

    _FAINT = 0.3

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._layer_z: float | None = None
        self._prev_layer_z: float | None = None
        self._ratios: list[float] = []
        self._faint = 0
        self._history: list[float] = []
        self._run_mm = 0.0
        self._run_reported = False
        self._abs_reported = False
        self._in_anomaly = False  # one finding per contiguous anomalous region

    # -------------------------------------------------------------- helpers
    def _baseline(self) -> float | None:
        if len(self._history) >= 3:
            return statistics.median(self._history[-_LAYER_HISTORY:])
        return None

    def _close_layer(self, ctx: Context | None, policy: Policy, final: bool = False) -> Iterable[Finding]:
        if self._layer_z is None:
            return
        z = fmt(round(self._layer_z, 3))
        baseline = self._baseline()
        if len(self._ratios) < 5:
            if baseline and self._faint >= 5 and not self._ratios and not final and not self._in_anomaly:
                self._in_anomaly = True
                yield self.hit(ctx, f"layer at Z={z} extrudes almost nothing (all moves under "
                                    f"{self._FAINT:.0%} of this print's typical amount per mm)",
                               layer_z=self._layer_z)
            return
        layer_median = statistics.median(self._ratios)
        sab = policy.sabotage
        in_band = baseline is None or (
            sab.layer_low_ratio * baseline <= layer_median <= sab.layer_high_ratio * baseline
        )
        if not in_band and not final and not self._in_anomaly and not self._run_reported:
            self._in_anomaly = True
            yield self.hit(
                ctx,
                f"layer at Z={z} extrudes {100 * layer_median / baseline:.0f}% of this print's "
                "typical amount per mm",
                layer_z=self._layer_z,
                ratio=layer_median / baseline,
            )
        elif in_band:
            self._history.append(layer_median)
            self._in_anomaly = False
        if not in_band and self._run_reported:
            self._in_anomaly = True
        yield from self._physics_check(ctx, policy, layer_median)

    def _physics_check(self, ctx: Context | None, policy: Policy, ratio: float) -> Iterable[Finding]:
        if self._abs_reported or self._prev_layer_z is None or self._layer_z is None:
            return
        height = self._layer_z - self._prev_layer_z
        if not 0.04 <= height <= policy.machine.max_layer_height_mm * 1.5:
            return
        machine = policy.machine
        area = math.pi * (machine.filament_diameter / 2) ** 2
        expected = (machine.nozzle_diameter * 1.125) * height / area
        if not 0.4 * expected <= ratio <= 3.5 * expected:
            self._abs_reported = True
            hint = ""
            if 0.33 <= ratio / expected <= 0.42 and machine.filament_diameter < 2:
                hint = " (sliced for 2.85mm filament? set machine.filament_diameter)"
            # Informational only: real slicer output is sometimes scaled by extruder
            # calibration we can't see, so this can't be trusted to block or warn.
            yield self.hit(
                ctx,
                f"layer at Z={fmt(round(self._layer_z, 3))} extrudes {100 * ratio / expected:.0f}% "
                f"of what a {fmt(machine.nozzle_diameter)}mm nozzle at {fmt(round(height, 3))}mm "
                f"layers physically needs{hint}",
                severity=Severity.INFO,
            )

    # ---------------------------------------------------------------- check
    def check(self, ctx: Context) -> Iterable[Finding]:
        motion, state = ctx.motion, ctx.state
        if motion is None or not state.is_printing:
            return
        if motion.e_delta <= 0 or motion.distance_xy < _MIN_SEGMENT_MM:
            return
        z = motion.physical["Z"]
        if self._layer_z is None or abs(z - self._layer_z) > 0.01:
            yield from self._close_layer(ctx, ctx.policy)
            if self._layer_z is not None and z > self._layer_z:
                self._prev_layer_z = self._layer_z
            self._layer_z, self._ratios, self._faint = z, [], 0
            self._run_mm, self._run_reported = 0.0, False
        ratio = motion.e_delta / motion.distance_xy * state.flow_percent / 100.0
        baseline = self._baseline()
        if baseline is not None and ratio < self._FAINT * baseline:
            self._faint += 1  # ironing / coasting pass
            return
        self._ratios.append(ratio)
        if baseline is None:
            return
        sab = ctx.policy.sabotage
        if ratio < sab.extrusion_low_ratio * baseline or ratio > sab.extrusion_high_ratio * baseline:
            self._run_mm += motion.distance_xy
        else:
            self._run_mm = 0.0
        if self._run_mm >= sab.extrusion_min_run_mm and not self._run_reported and not self._in_anomaly:
            self._run_reported = True
            yield self.hit(
                ctx,
                f"{fmt(round(self._run_mm))}mm of consecutive extrusion at {100 * ratio / baseline:.0f}% "
                "of the print's baseline",
            )

    def finish(self, state: MachineState, policy: Policy) -> Iterable[Finding]:
        yield from self._close_layer(None, policy, final=True)
