"""Machine state tracking, so rules can reason about *where* and *when* a command lands."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from gcodeguard.commands import MOTION_CODES, heater_targets
from gcodeguard.gcode import Command

AXES = ("X", "Y", "Z", "E")
_PRINT_START_EXTRUSION_MM = 5.0


@dataclass(frozen=True)
class Motion:
    """Projected effect of a G0-G3 move, computed before the move runs."""

    target: dict[str, float]  # logical coordinates after the move
    physical: dict[str, float]  # machine coordinates after the move (logical + offset)
    distance_xy: float
    distance: float
    e_delta: float
    duration_s: float
    feedrate: float | None  # F word on this line, mm/min


@dataclass
class MachineState:
    homed: set[str] = field(default_factory=set)
    position: dict[str, float] = field(default_factory=lambda: dict.fromkeys(AXES, 0.0))
    offsets: dict[str, float] = field(default_factory=lambda: dict.fromkeys(AXES, 0.0))
    absolute: bool = True
    relative_e: bool = False
    inches: bool = False
    feedrate: float = 1500.0
    active_tool: int = 0
    hotend_target: dict[int, float] = field(default_factory=dict)
    bed_target: float = 0.0
    chamber_target: float = 0.0
    clock_s: float = 0.0
    last_activity_s: float = 0.0
    extruded_mm: float = 0.0
    printing: bool = False
    printing_override: bool | None = None
    print_temp: float | None = None
    flow_percent: float = 100.0
    speed_percent: float = 100.0
    last_extrude_z: float | None = None
    steppers_enabled: bool = True
    software_endstops: bool = True
    cold_extrusion_allowed: bool = False
    lines_seen: int = 0
    end_macro_seen: bool = False  # PRINT_END-style macro: heaters are switched off inside it

    # ------------------------------------------------------------------ queries
    @property
    def is_printing(self) -> bool:
        return self.printing if self.printing_override is None else self.printing_override

    def heaters_on(self, threshold: float) -> bool:
        return (
            any(t > threshold for t in self.hotend_target.values())
            or self.bed_target > threshold
            or self.chamber_target > threshold
        )

    def physical(self, axis: str) -> float:
        return self.position[axis] + self.offsets[axis]

    # --------------------------------------------------------------- projection
    def project(self, cmd: Command) -> Motion | None:
        if cmd.code not in MOTION_CODES:
            return None
        scale = 25.4 if self.inches else 1.0
        target = dict(self.position)
        for axis in AXES:
            value = cmd.num(axis)
            if value is None:
                continue
            value *= scale
            relative = (not self.absolute) or (axis == "E" and self.relative_e)
            target[axis] = self.position[axis] + value if relative else value
        physical = {a: target[a] + self.offsets[a] for a in AXES}
        dx = target["X"] - self.position["X"]
        dy = target["Y"] - self.position["Y"]
        dz = target["Z"] - self.position["Z"]
        e_delta = target["E"] - self.position["E"]
        distance_xy = _arc_length(cmd, self.position, target, scale) or math.hypot(dx, dy)
        distance = math.sqrt(dx * dx + dy * dy + dz * dz) or abs(e_delta)
        f_word = cmd.num("F")
        feed = (f_word * scale if f_word else self.feedrate) or 1.0
        effective = feed * max(self.speed_percent, 1.0) / 100.0
        duration = distance / (effective / 60.0) if distance else 0.0
        return Motion(target, physical, distance_xy, distance, e_delta, duration,
                      f_word * scale if f_word else None)

    # ------------------------------------------------------------------- update
    def apply(self, cmd: Command, motion: Motion | None) -> None:
        """Advance the state as if the printer executed ``cmd``."""
        self.lines_seen += 1
        code = cmd.code
        if motion is not None:
            self._apply_motion(motion)
            return
        for heater in heater_targets(cmd, self.active_tool):
            self._set_heater(heater.heater, heater.index, heater.target)
        handler = _HANDLERS.get(code)
        if handler is not None:
            handler(self, cmd)

    def _apply_motion(self, motion: Motion) -> None:
        if motion.feedrate:
            self.feedrate = motion.feedrate
        self.position = dict(motion.target)
        self.clock_s += motion.duration_s
        if motion.distance > 0:
            self.last_activity_s = self.clock_s
        if motion.e_delta > 0 and motion.distance_xy > 0:
            self.extruded_mm += motion.e_delta
            self.last_extrude_z = motion.physical["Z"]
            if (
                not self.printing
                and self.extruded_mm >= _PRINT_START_EXTRUSION_MM
                and any(t > 0 for t in self.hotend_target.values())
            ):
                self.printing = True
                self.print_temp = self.hotend_target.get(self.active_tool)

    def _set_heater(self, heater: str, index: int, target: float) -> None:
        if heater == "hotend":
            self.hotend_target[index] = target
            if target <= 0 and self.printing:
                self.printing = False  # end-of-print sequence
            elif self.printing and index == self.active_tool and self.print_temp is None:
                self.print_temp = target
        elif heater == "bed":
            self.bed_target = target
        else:
            self.chamber_target = target


def _arc_length(cmd: Command, start: dict[str, float], end: dict[str, float], scale: float) -> float:
    """XY length of a G2/G3 arc (I/J centre or R radius form); 0 for straight moves."""
    if cmd.code not in {"G2", "G3"}:
        return 0.0
    sx, sy, ex, ey = start["X"], start["Y"], end["X"], end["Y"]
    chord = math.hypot(ex - sx, ey - sy)
    if cmd.has("R"):
        radius = abs((cmd.num("R") or 0.0) * scale)
        if radius <= 0 or chord > 2 * radius:
            return chord
        angle = 2 * math.asin(chord / (2 * radius))
        if (cmd.num("R") or 0.0) < 0:
            angle = 2 * math.pi - angle
        return radius * angle
    i, j = (cmd.num("I", 0.0) or 0.0) * scale, (cmd.num("J", 0.0) or 0.0) * scale
    radius = math.hypot(i, j)
    if radius == 0:
        return chord
    cx, cy = sx + i, sy + j
    a0, a1 = math.atan2(sy - cy, sx - cx), math.atan2(ey - cy, ex - cx)
    sweep = (a0 - a1) if cmd.code == "G2" else (a1 - a0)
    sweep %= 2 * math.pi
    if sweep < 1e-9:
        sweep = 2 * math.pi  # full circle
    return radius * sweep


def _home(state: MachineState, cmd: Command) -> None:
    axes = [a for a in ("X", "Y", "Z") if cmd.has(a)] or ["X", "Y", "Z"]
    for axis in axes:
        state.homed.add(axis)
        state.offsets[axis] = 0.0
        state.position[axis] = 0.0
    state.steppers_enabled = True


def _set_position(state: MachineState, cmd: Command) -> None:
    scale = 25.4 if state.inches else 1.0
    present = [a for a in AXES if cmd.has(a)] or list(AXES)
    for axis in present:
        value = (cmd.num(axis, 0.0) or 0.0) * scale
        physical = state.physical(axis)
        state.position[axis] = value
        if axis != "E":
            state.offsets[axis] = physical - value


def _klipper_set_position(state: MachineState, cmd: Command) -> None:
    for axis in ("X", "Y", "Z"):
        value = cmd.num(axis)
        if value is not None:
            state.position[axis] = value
            state.offsets[axis] = 0.0
            state.homed.add(axis)


def _dwell(state: MachineState, cmd: Command) -> None:
    state.clock_s += dwell_seconds(cmd)


def dwell_seconds(cmd: Command) -> float:
    if cmd.code != "G4":
        return 0.0
    seconds = cmd.num("S")
    if seconds is not None:
        return max(seconds, 0.0)
    return max(cmd.num("P", 0.0) or 0.0, 0.0) / 1000.0


def _disable_steppers(state: MachineState, cmd: Command) -> None:
    if cmd.has("S") and not any(cmd.has(a) for a in AXES):
        return  # M84 S<seconds> only sets the idle timeout
    state.steppers_enabled = False
    axes = [a for a in ("X", "Y", "Z") if cmd.has(a)] or ["X", "Y", "Z"]
    for axis in axes:
        state.homed.discard(axis)


def _set_attr(name: str, value: object):
    def handler(state: MachineState, cmd: Command) -> None:
        setattr(state, name, value)

    return handler


def _endstops(state: MachineState, cmd: Command) -> None:
    value = cmd.num("S")
    if value is not None:
        state.software_endstops = bool(value)


def _cold_extrusion(state: MachineState, cmd: Command) -> None:
    if cmd.num("P") == 1 or cmd.num("S") == 0:
        state.cold_extrusion_allowed = True
    elif cmd.num("P") == 0:
        state.cold_extrusion_allowed = False


def _factor(name: str):
    def handler(state: MachineState, cmd: Command) -> None:
        value = cmd.num("S")
        if value is not None:
            setattr(state, name, value)

    return handler


END_MACROS = frozenset({"PRINT_END", "END_PRINT"})


def _end_macro(state: MachineState, cmd: Command) -> None:
    state.end_macro_seen = True
    state.printing = False


def _tool(state: MachineState, cmd: Command) -> None:
    state.active_tool = int(cmd.code[1:])


_HANDLERS = {
    "G28": _home,
    "G92": _set_position,
    "SET_KINEMATIC_POSITION": _klipper_set_position,
    "G4": _dwell,
    "G90": _set_attr("absolute", True),
    "G91": _set_attr("absolute", False),
    "M82": _set_attr("relative_e", False),
    "M83": _set_attr("relative_e", True),
    "G20": _set_attr("inches", True),
    "G21": _set_attr("inches", False),
    "M17": _set_attr("steppers_enabled", True),
    "M18": _disable_steppers,
    "M84": _disable_steppers,
    "M211": _endstops,
    "M302": _cold_extrusion,
    "M220": _factor("speed_percent"),
    "M221": _factor("flow_percent"),
    **{f"T{i}": _tool for i in range(10)},
    **dict.fromkeys(END_MACROS, _end_macro),
}
