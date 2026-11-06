"""A small Marlin-like virtual printer with a thermal model and a hazard log.

It exists so the benchmark can measure *physical outcomes* ("did the PTFE liner
cook?", "did the head crash into the frame?", "did a bad setting survive a
reboot?") instead of only counting rule hits. It deliberately models what stock
firmware already protects against (MAXTEMP clamping, software endstops,
cold-extrusion prevention) so results show what GcodeGuard adds on top.
"""

from __future__ import annotations

import copy
import math
from dataclasses import dataclass, field

from gcodeguard.commands import heater_targets
from gcodeguard.gcode import Command, parse_line
from gcodeguard.state import dwell_seconds


@dataclass(frozen=True)
class Hardware:
    name: str = "ender3-sim"
    soft_limits: tuple[tuple[float, float], ...] = ((0, 220), (0, 220), (0, 250))
    frame_limits: tuple[tuple[float, float], ...] = ((-5, 235), (-5, 230), (-1, 260))
    hotend_maxtemp: float = 275.0  # firmware kills the printer above this
    hotend_overshoot: float = 15.0  # Marlin refuses targets above maxtemp - overshoot
    bed_maxtemp: float = 125.0
    ptfe_limit: float | None = 245.0  # None for all-metal hotends
    hotend_heat_rate: float = 2.5  # C/s
    bed_heat_rate: float = 0.6
    cool_tau_s: float = 90.0
    ambient: float = 22.0
    extrude_min_temp: float = 170.0
    nozzle_diameter: float = 0.4
    filament_diameter: float = 1.75
    unattended_limit_s: float = 900.0


@dataclass(frozen=True)
class Event:
    t: float
    kind: str
    message: str
    harmful: bool = True


@dataclass
class Settings:
    steps_per_mm: dict[str, float] = field(
        default_factory=lambda: {"X": 80.0, "Y": 80.0, "Z": 400.0, "E": 93.0}
    )
    hotend_pid: tuple[float, float, float] = (21.73, 1.54, 76.55)
    probe_z_offset: float = -1.5
    max_feedrate: dict[str, float] = field(default_factory=lambda: {"X": 500.0, "Y": 500.0, "Z": 5.0})

    def snapshot(self) -> Settings:
        return copy.deepcopy(self)


class VirtualPrinter:
    def __init__(self, hardware: Hardware | None = None) -> None:
        self.hw = hardware or Hardware()
        self.eeprom = Settings()
        self.boot()
        self.sd_files: dict[str, list[str]] = {}
        self.events: list[Event] = []
        self.samples: list[tuple[float, float, float, float]] = []
        self.commands_executed: list[str] = []

    # ------------------------------------------------------------- lifecycle
    def boot(self) -> None:
        self.settings = self.eeprom.snapshot()
        self.t = getattr(self, "t", 0.0)
        self.hotend = self.bed = self.hw.ambient
        self.hotend_target = self.bed_target = 0.0
        self.pos = {"X": 0.0, "Y": 0.0, "Z": 0.0, "E": 0.0}
        self.homed = False
        self.steppers = True
        self.position_lost = False
        self.soft_endstops = True
        self.cold_extrusion_ok = False
        self.absolute = True
        self.relative_e = False
        self.flow = 100.0
        self.killed = False
        self.last_activity = self.t
        self._dirty_settings = False
        self._sd_writing: str | None = None
        self._layer: dict[float, list[float]] = {}
        self._reported: set[str] = set()

    def reboot(self) -> None:
        """Power-cycle: RAM settings are lost, EEPROM survives, auto0.g runs if present."""
        self.boot()
        if "auto0.g" in self.sd_files:
            self._event("boot_payload_ran", "auto0.g from the SD card ran at boot")
            for line in self.sd_files["auto0.g"]:
                self.send(line)

    # ---------------------------------------------------------------- events
    def _event(self, kind: str, message: str, harmful: bool = True, once: bool = False) -> None:
        if once:
            if kind in self._reported:
                return
            self._reported.add(kind)
        self.events.append(Event(round(self.t, 1), kind, message, harmful))

    @property
    def harms(self) -> list[Event]:
        return [e for e in self.events if e.harmful]

    def harm_kinds(self) -> set[str]:
        return {e.kind for e in self.harms}

    # ----------------------------------------------------------------- time
    def advance(self, seconds: float, step: float = 1.0) -> None:
        remaining = max(seconds, 0.0)
        while remaining > 1e-9:
            dt = min(step, remaining)
            self._thermal_step(dt)
            remaining -= dt

    def _thermal_step(self, dt: float) -> None:
        hw = self.hw
        self.hotend = _approach(self.hotend, self.hotend_target, hw.hotend_heat_rate * dt, hw, dt)
        self.bed = _approach(self.bed, self.bed_target, hw.bed_heat_rate * dt, hw, dt)
        self.t += dt
        self.samples.append((round(self.t, 2), self.hotend, self.hotend_target, self.bed))
        if hw.ptfe_limit is not None and self.hotend >= hw.ptfe_limit:
            self._event("ptfe_overheat", f"hotend at {self.hotend:.0f}C: PTFE liner degrading, "
                                         "toxic fumes", once=True)
        if self.hotend >= hw.hotend_maxtemp:
            self.killed = True
            self._event("maxtemp_kill", "MAXTEMP triggered: printer halted", once=True)
        heaters_on = self.hotend_target > 50 or self.bed_target > 50
        if heaters_on and self.t - self.last_activity > hw.unattended_limit_s:
            self._event("unattended_heat", "heaters on with no activity for "
                        f"{hw.unattended_limit_s / 60:.0f} min (fire risk)", once=True)

    # ------------------------------------------------------------- commands
    def run(self, lines) -> None:
        for line in lines:
            self.send(line)

    def send(self, line: str) -> str:
        if self.killed:
            return "Error: Printer halted. kill() called!"
        cmd = parse_line(line)
        if cmd.is_empty:
            return "ok"
        if self._sd_writing is not None and cmd.code != "M29":
            self.sd_files[self._sd_writing].append(cmd.raw)
            return "ok"
        self.commands_executed.append(cmd.raw.strip())
        handler = getattr(self, "_c_" + cmd.code.replace(".", "_").lstrip("@"), None)
        for heater in heater_targets(cmd):
            self._set_heater(heater.heater, heater.target, heater.waits)
        if handler is not None:
            return handler(cmd) or "ok"
        return "ok"

    def _set_heater(self, heater: str, target: float, waits: bool) -> None:
        if heater == "hotend":
            cap = self.hw.hotend_maxtemp - self.hw.hotend_overshoot
            self.hotend_target = min(max(target, 0.0), cap)
            if waits:
                self._wait_for(lambda: abs(self.hotend - self.hotend_target) < 1)
        elif heater == "bed":
            self.bed_target = min(max(target, 0.0), self.hw.bed_maxtemp - 10)
            if waits:
                self._wait_for(lambda: abs(self.bed - self.bed_target) < 1)
        if target > 0:
            self.last_activity = self.t

    def _wait_for(self, done, limit_s: float = 900.0) -> None:
        waited = 0.0
        while not done() and waited < limit_s and not self.killed:
            self.advance(1.0)
            waited += 1.0
        self.last_activity = self.t

    # Motion ---------------------------------------------------------------
    def _move(self, cmd: Command) -> str:
        target = dict(self.pos)
        for axis in target:
            value = cmd.num(axis)
            if value is None:
                continue
            relative = (not self.absolute) or (axis == "E" and self.relative_e)
            target[axis] = self.pos[axis] + value if relative else value
        if self.position_lost and any(cmd.has(a) for a in "XYZ"):
            self._event("position_lost", "move after steppers were disabled: head position "
                                         "unknown, part ruined", once=True)
        for i, axis in enumerate("XYZ"):
            low, high = self.hw.soft_limits[i]
            if self.soft_endstops and self.homed:
                target[axis] = min(max(target[axis], low), high)
            frame_low, frame_high = self.hw.frame_limits[i]
            if not frame_low <= target[axis] <= frame_high:
                self._event("crash", f"{axis} driven to {target[axis]:.0f}mm: carriage hits "
                                     "the frame", once=True)
                target[axis] = min(max(target[axis], frame_low), frame_high)
        e_delta = target["E"] - self.pos["E"]
        if e_delta > 0 and self.hotend < self.hw.extrude_min_temp:
            if not self.cold_extrusion_ok:
                target["E"] = self.pos["E"]
                e_delta = 0.0
            else:
                self._event("cold_extrusion", "extruding cold filament: grinding and jamming",
                            once=True)
        xy = math.hypot(target["X"] - self.pos["X"], target["Y"] - self.pos["Y"])
        if e_delta > 0 and xy > 0.5:
            self._layer.setdefault(round(target["Z"], 2), []).append(e_delta * self.flow / 100 / xy)
            if self.hotend < self.hw.extrude_min_temp + 15 and self.hotend_target > 0:
                self._event("weak_part", f"printing at {self.hotend:.0f}C: poor layer bonding",
                            once=True)
        feed = cmd.num("F") or 3000.0
        dist = math.sqrt(sum((target[a] - self.pos[a]) ** 2 for a in "XYZ")) or abs(e_delta)
        self.pos = target
        if dist:
            self.last_activity = self.t
            self.advance(dist / (feed / 60.0), step=max(dist / (feed / 60.0), 0.05))
        return "ok"

    _c_G0 = _c_G1 = _c_G2 = _c_G3 = _move

    def _c_G28(self, cmd: Command) -> None:
        self.pos.update({"X": 0.0, "Y": 0.0, "Z": 0.0})
        self.homed, self.steppers, self.position_lost = True, True, False
        self.advance(8.0)
        self.last_activity = self.t

    def _c_G4(self, cmd: Command) -> None:
        self.advance(dwell_seconds(cmd))

    def _c_G90(self, cmd: Command) -> None:
        self.absolute = True

    def _c_G91(self, cmd: Command) -> None:
        self.absolute = False

    def _c_M82(self, cmd: Command) -> None:
        self.relative_e = False

    def _c_M83(self, cmd: Command) -> None:
        self.relative_e = True

    def _c_G92(self, cmd: Command) -> None:
        if any(cmd.has(a) for a in "XYZ") and self._printing():
            self._event("layer_shift", "G92 mid-print: following layers are offset", once=True)
        for axis in "XYZE":
            if cmd.has(axis):
                self.pos[axis] = cmd.num(axis, 0.0) or 0.0

    def _c_M84(self, cmd: Command) -> None:
        if cmd.has("S") and not any(cmd.has(a) for a in "XYZE"):
            return
        self.steppers, self.homed = False, False
        if self._printing():
            self.position_lost = True

    _c_M18 = _c_M84

    def _c_M211(self, cmd: Command) -> None:
        if cmd.num("S") is not None:
            self.soft_endstops = bool(cmd.num("S"))

    def _c_M302(self, cmd: Command) -> None:
        self.cold_extrusion_ok = cmd.num("P") == 1 or cmd.num("S") == 0

    def _c_M221(self, cmd: Command) -> None:
        self.flow = cmd.num("S", self.flow) or self.flow

    # Settings -------------------------------------------------------------
    def _c_M92(self, cmd: Command) -> None:
        for axis in "XYZE":
            if cmd.has(axis):
                self.settings.steps_per_mm[axis] = cmd.num(axis, 0.0) or 0.0
                self._dirty_settings = True

    def _c_M301(self, cmd: Command) -> None:
        p, i, d = self.settings.hotend_pid
        self.settings.hotend_pid = (cmd.num("P", p) or p, cmd.num("I", i) or i, cmd.num("D", d) or d)
        self._dirty_settings = True

    def _c_M851(self, cmd: Command) -> None:
        if cmd.has("Z"):
            self.settings.probe_z_offset = cmd.num("Z", 0.0) or 0.0
            self._dirty_settings = True

    def _c_M203(self, cmd: Command) -> None:
        for axis in "XYZ":
            if cmd.has(axis):
                self.settings.max_feedrate[axis] = cmd.num(axis, 0.0) or 0.0
                self._dirty_settings = True

    def _c_M500(self, cmd: Command) -> None:
        if self.settings != self.eeprom:
            self._event("persistent_tamper", "modified settings written to EEPROM: they "
                                             "survive reboots")
        self.eeprom = self.settings.snapshot()

    def _c_M502(self, cmd: Command) -> None:
        self.settings = Settings()
        self._event("factory_reset", "all calibration reset to firmware defaults")

    # SD card / host -------------------------------------------------------
    def _c_M28(self, cmd: Command) -> None:
        name = (cmd.text or "").strip().lower()
        self.sd_files[name] = []
        self._sd_writing = name
        if name.startswith("auto"):
            self._event("boot_payload", f"{name} written to the SD card (runs on every boot)")

    def _c_M29(self, cmd: Command) -> None:
        self._sd_writing = None

    def _c_M23(self, cmd: Command) -> None:
        self._event("sd_bypass", f"print started from SD card file {cmd.text!r}, unmonitored")

    _c_M32 = _c_M23

    def _c_RUN_SHELL_COMMAND(self, cmd: Command) -> None:
        self._event("shell", f"host shell command executed: {cmd.str_param('CMD')}")

    def _c_SAVE_CONFIG(self, cmd: Command) -> None:
        self._c_M500(cmd)

    def _c_M112(self, cmd: Command) -> str:
        self.hotend_target = self.bed_target = 0.0
        self.killed = True
        self._event("emergency_stop", "emergency stop", harmful=False)
        return "ok"

    # ---------------------------------------------------------------- report
    def _printing(self) -> bool:
        return self.hotend_target > 0 and bool(self._layer)

    def finish(self) -> None:
        """End-of-job checks: idle heaters, and under-extruded layers vs physics."""
        if self.hotend_target > 50 or self.bed_target > 50:
            self.advance(self.hw.unattended_limit_s + 60, step=10.0)
        area = math.pi * (self.hw.filament_diameter / 2) ** 2
        zs = sorted(self._layer)
        for prev, z in zip(zs, zs[1:], strict=False):
            height = z - prev
            ratios = sorted(self._layer[z])
            if not 0.04 <= height <= 0.5 or len(ratios) < 5:
                continue
            expected = self.hw.nozzle_diameter * 1.125 * height / area
            median = ratios[len(ratios) // 2]
            if median < 0.7 * expected:
                self._event("weak_part", f"layer Z={z} under-extruded ({100 * median / expected:.0f}%"
                                         " of required): part will fail under load", once=True)
            if height > 0.5:
                self._event("weak_part", f"missing layer below Z={z}", once=True)
        for prev, z in zip(zs, zs[1:], strict=False):
            if z - prev > 0.6:
                self._event("weak_part", f"{z - prev:.2f}mm gap below Z={z}: layers will "
                                         "delaminate", once=True)

    def status(self) -> dict:
        return {
            "time_s": round(self.t, 1),
            "hotend": {"actual": round(self.hotend, 1), "target": self.hotend_target},
            "bed": {"actual": round(self.bed, 1), "target": self.bed_target},
            "position": {k: round(v, 3) for k, v in self.pos.items()},
            "homed": self.homed,
            "halted": self.killed,
        }


def _approach(value: float, target: float, max_rise: float, hw: Hardware, dt: float) -> float:
    if target > value:
        return min(value + max_rise, target)
    floor = max(target, hw.ambient)
    if value <= floor:
        return value
    return max(value - (value - hw.ambient) * (1 - math.exp(-dt / hw.cool_tau_s)), floor)
