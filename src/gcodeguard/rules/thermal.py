"""Thermal rules: over-temperature, idle heaters, disabled interlocks."""

from __future__ import annotations

from collections.abc import Iterable

from gcodeguard.commands import heater_targets
from gcodeguard.model import Category, Finding, Severity
from gcodeguard.policy import Policy
from gcodeguard.rules.base import Context, Rule, fmt
from gcodeguard.state import MachineState, dwell_seconds

_LIMIT_ATTR = {"hotend": "max_hotend_temp", "bed": "max_bed_temp", "chamber": "max_chamber_temp"}
_PARAM_FOR = {"SET_HEATER_TEMPERATURE": "TARGET", "PID_CALIBRATE": "TARGET", "MPC_CALIBRATE": "TARGET"}


class HeaterLimit(Rule):
    id = "thermal.heater_limit"
    category = Category.THERMAL
    severity = Severity.CRITICAL
    summary = "Heater setpoint above the machine's safe limit (hotend, bed, chamber)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        for heater in heater_targets(ctx.cmd, ctx.state.active_tool):
            limit = getattr(ctx.policy.machine, _LIMIT_ATTR[heater.heater])
            if heater.target > limit:
                param = _PARAM_FOR.get(ctx.cmd.code, "S" if ctx.cmd.has("S") else "R")
                yield self.hit(
                    ctx,
                    f"{heater.heater} target {fmt(heater.target)}C exceeds the "
                    f"{fmt(limit)}C limit for this machine",
                    clamp={param: fmt(limit)},
                    heater=heater.heater,
                    target=heater.target,
                    limit=limit,
                )


class LongDwellWhileHot(Rule):
    id = "thermal.idle_heater"
    category = Category.THERMAL
    severity = Severity.CRITICAL
    summary = "Heaters left on while the machine sits idle (long dwell, or never switched off)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        seconds = dwell_seconds(ctx.cmd)
        if seconds <= ctx.policy.thermal.max_dwell_s:
            return
        if not ctx.state.heaters_on(ctx.policy.thermal.idle_heater_threshold_c):
            return
        yield self.hit(
            ctx,
            f"dwell of {fmt(seconds)}s with heaters on (max {fmt(ctx.policy.thermal.max_dwell_s)}s)",
            seconds=seconds,
        )

    def finish(self, state: MachineState, policy: Policy) -> Iterable[Finding]:
        if state.end_macro_seen:
            return  # the slicer handed off to an end macro, which switches heaters off
        if state.lines_seen and state.heaters_on(policy.thermal.idle_heater_threshold_c):
            on = [f"T{i}={fmt(t)}C" for i, t in state.hotend_target.items() if t > 0]
            if state.bed_target > 0:
                on.append(f"bed={fmt(state.bed_target)}C")
            yield self.hit(
                None,
                "file ends with heaters still on (" + ", ".join(on) + "); the printer will sit "
                "hot and unattended",
                severity=Severity.WARNING,
            )


class ColdExtrusionUnlock(Rule):
    id = "thermal.cold_extrusion_unlock"
    category = Category.THERMAL
    severity = Severity.CRITICAL
    summary = "M302 disables the firmware interlock against extruding cold filament."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd = ctx.cmd
        if cmd.code == "M302" and (cmd.num("P") == 1 or cmd.num("S") == 0):
            yield self.hit(ctx, "M302 disables cold-extrusion protection (grinds filament, "
                                "jams the hotend, hides heater faults)")


class LowPrintTemperature(Rule):
    id = "thermal.low_print_temp"
    category = Category.THERMAL
    severity = Severity.WARNING
    summary = "Hotend set below the minimum printing temperature while printing."

    def check(self, ctx: Context) -> Iterable[Finding]:
        if not ctx.state.is_printing:
            return
        for heater in heater_targets(ctx.cmd, ctx.state.active_tool):
            if heater.heater != "hotend" or heater.index != ctx.state.active_tool:
                continue  # standby temperature for an idle tool is fine
            if 0 < heater.target < ctx.policy.machine.min_print_temp:
                yield self.hit(
                    ctx,
                    f"hotend set to {fmt(heater.target)}C mid-print, below the "
                    f"{fmt(ctx.policy.machine.min_print_temp)}C minimum",
                )
