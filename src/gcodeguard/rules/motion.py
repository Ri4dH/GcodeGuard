"""Motion rules: build-volume bounds, speeds, endstops, position tampering."""

from __future__ import annotations

from collections.abc import Iterable

from gcodeguard.model import Category, Finding, Severity
from gcodeguard.rules.base import Context, Rule, fmt


class OutOfBounds(Rule):
    id = "motion.out_of_bounds"
    category = Category.MOTION
    severity = Severity.CRITICAL
    summary = "Move would leave the build volume (crash into the frame or bed)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        if ctx.motion is None:
            return
        machine = ctx.policy.machine
        for axis, bounds in machine.build_volume.items():
            if axis not in ctx.state.homed:
                continue  # position unknown; firmware will refuse or home first
            value = ctx.motion.physical[axis]
            if not bounds.contains(value, machine.bounds_margin_mm):
                yield self.hit(
                    ctx,
                    f"{axis}={fmt(value)}mm is outside the build volume "
                    f"[{fmt(bounds.low)}, {fmt(bounds.high)}]",
                    axis=axis,
                    value=value,
                )


class FeedrateLimit(Rule):
    id = "motion.feedrate_limit"
    category = Category.MOTION
    severity = Severity.WARNING
    summary = "Commanded feedrate above the machine's maximum speed."

    def check(self, ctx: Context) -> Iterable[Finding]:
        if ctx.motion is None or ctx.motion.feedrate is None:
            return
        limit = ctx.policy.machine.max_feedrate_mm_s * 60
        if ctx.motion.feedrate > limit:
            yield self.hit(
                ctx,
                f"feedrate F{fmt(ctx.motion.feedrate)} ({fmt(ctx.motion.feedrate / 60)}mm/s) "
                f"exceeds {fmt(limit / 60)}mm/s",
                clamp={"F": fmt(limit)},
            )


class LimitsTamper(Rule):
    id = "motion.limits_tamper"
    category = Category.MOTION
    severity = Severity.WARNING
    summary = "Raises firmware speed/acceleration/current limits."

    _FEED = {"M203"}
    _ACCEL = {"M201", "M204"}

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd, machine = ctx.cmd, ctx.policy.machine
        values: list[tuple[str, float, float]] = []
        if cmd.code in self._FEED:
            values = [(k, v, machine.max_feedrate_mm_s) for k in "XYZ" if (v := cmd.num(k))]
        elif cmd.code in self._ACCEL:
            values = [(k, v, machine.max_accel_mm_s2) for k in "XYZPTS" if (v := cmd.num(k))]
        elif cmd.code == "SET_VELOCITY_LIMIT":
            if (v := cmd.num("VELOCITY")) is not None:
                values.append(("VELOCITY", v, machine.max_feedrate_mm_s))
            if (v := cmd.num("ACCEL")) is not None:
                values.append(("ACCEL", v, machine.max_accel_mm_s2))
        elif cmd.code in {"M906", "SET_TMC_CURRENT", "M907"}:
            yield self.hit(ctx, f"{cmd.code} changes stepper motor current (overheats drivers "
                                "and motors when raised)", severity=Severity.INFO)
            return
        elif cmd.code == "SET_TMC_FIELD":
            yield self.hit(ctx, "SET_TMC_FIELD writes raw stepper-driver registers",
                           severity=Severity.CRITICAL)
            return
        for key, value, limit in values:
            if value > limit:
                yield self.hit(
                    ctx,
                    f"{cmd.code} raises {key} to {fmt(value)} (machine limit {fmt(limit)})",
                    severity=Severity.CRITICAL,
                )


class EndstopsDisabled(Rule):
    id = "motion.endstops_disabled"
    category = Category.MOTION
    severity = Severity.CRITICAL
    summary = "Disables software or hardware endstops, removing travel limits."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd = ctx.cmd
        if cmd.code == "M211" and cmd.num("S") == 0:
            yield self.hit(ctx, "M211 S0 disables software endstops: moves are no longer "
                                "limited to the build volume")
        elif cmd.code == "M121":
            yield self.hit(ctx, "M121 disables endstop detection")
        elif cmd.code == "FORCE_MOVE":
            yield self.hit(ctx, "FORCE_MOVE moves a stepper with no kinematic or "
                                "endstop checks")


class PositionOverride(Rule):
    id = "motion.position_override"
    category = Category.MOTION
    severity = Severity.CRITICAL
    summary = "Rewrites the machine's idea of where it is (layer shifts, bounds bypass)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd, state = ctx.cmd, ctx.state
        if cmd.code == "G92":
            axes = [a for a in ("X", "Y", "Z") if cmd.has(a)]
            if not cmd.params:
                axes = ["X", "Y", "Z"]
            if axes and state.is_printing:
                yield self.hit(ctx, f"G92 redefines {'/'.join(axes)} mid-print: shifts every "
                                    "following layer (classic layer-shift sabotage)")
            elif axes and any(abs((cmd.num(a, 0) or 0) - state.physical(a)) > 1.0 for a in axes):
                yield self.hit(ctx, f"G92 offsets {'/'.join(axes)} away from the homed position: "
                                    "build-volume checks no longer match reality",
                               severity=Severity.WARNING)
        elif cmd.code == "SET_KINEMATIC_POSITION":
            yield self.hit(ctx, "SET_KINEMATIC_POSITION tells Klipper it is somewhere it may "
                                "not be")
        elif cmd.code in {"M206", "M428"}:
            yield self.hit(ctx, f"{cmd.code} changes home offsets: the whole coordinate system "
                                "moves", severity=Severity.WARNING)
        elif cmd.code == "SET_GCODE_OFFSET" and state.is_printing:
            z = cmd.num("Z") or cmd.num("Z_ADJUST")
            if z is not None and abs(z) > 0.5:
                yield self.hit(ctx, f"SET_GCODE_OFFSET moves Z by {fmt(z)}mm mid-print")


class SteppersDisabledMidPrint(Rule):
    id = "motion.steppers_disabled"
    category = Category.MOTION
    severity = Severity.CRITICAL
    summary = "Steppers switched off while printing with heaters on (lost position, crash)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd, state = ctx.cmd, ctx.state
        stepper_off = cmd.code in {"M18", "M84"} and not (
            cmd.has("S") and not any(cmd.has(a) for a in "XYZE")
        )
        if cmd.code == "SET_STEPPER_ENABLE" and cmd.num("ENABLE") == 0:
            stepper_off = True
        if not stepper_off:
            return
        if state.is_printing and any(t > 0 for t in state.hotend_target.values()):
            yield self.hit(ctx, f"{cmd.code} disables steppers mid-print with the hotend hot: "
                                "position is lost and the next move lands anywhere")
