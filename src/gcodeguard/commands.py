"""Catalog of G-code commands GcodeGuard understands, plus heater helpers."""

from __future__ import annotations

from dataclasses import dataclass

from gcodeguard.gcode import Command

MOTION_CODES = frozenset({"G0", "G1", "G2", "G3"})

#: Commands that only ever make the machine *safer*. They are never blocked,
#: whatever the policy says, so an emergency stop always gets through.
SAFETY_COMMANDS = frozenset(
    {
        "M112",  # emergency stop
        "M108",  # break out of heating wait
        "M410",  # quickstop
        "M524",  # abort SD print
        "M81",  # power off
        "EMERGENCY_STOP",
        "CANCEL_PRINT",
        "TURN_OFF_HEATERS",
        "PAUSE",
        "@PAUSE",
        "@ABORT",
        "@CANCEL",
    }
)

_G = {
    0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 17, 18, 19, 20, 21, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 38, 42, 53, 54, 55, 56, 57, 58, 59, 60, 61, 76, 80, 90, 91, 92, 425,
}
_M = {
    0, 1, 3, 4, 5, 7, 8, 9, 10, 11, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 42, 43, 48, 73, 75, 76, 77, 78, 80, 81, 82, 83, 84, 85, 86, 87, 92, 100,
    102, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 117, 118, 119, 120, 121,
    122, 123, 125, 126, 127, 128, 129, 140, 141, 143, 145, 149, 150, 154, 155, 163, 164, 165,
    166, 190, 191, 192, 193, 200, 201, 203, 204, 205, 206, 207, 208, 209, 211, 217, 218, 220,
    221, 226, 240, 250, 255, 256, 260, 261, 280, 281, 282, 290, 300, 301, 302, 303, 304, 305,
    306, 350, 351, 355, 360, 380, 381, 400, 401, 402, 403, 404, 405, 406, 407, 410, 412, 413,
    420, 421, 422, 423, 425, 428, 430, 486, 493, 500, 501, 502, 503, 504, 510, 511, 512, 524,
    540, 569, 575, 592, 593, 600, 603, 605, 665, 666, 672, 701, 702, 710, 808, 851, 852, 860,
    861, 862, 863, 864, 865, 866, 867, 868, 869, 871, 876, 900, 906, 907, 908, 909, 910, 911,
    912, 913, 914, 915, 916, 917, 918, 919, 928, 951, 993, 994, 995, 997, 999, 7219,
}

KLIPPER_COMMANDS = frozenset(
    ["SET_HEATER_TEMPERATURE", "TEMPERATURE_WAIT", "SET_FAN_SPEED", "SET_PRESSURE_ADVANCE", "SET_VELOCITY_LIMIT", "SET_KINEMATIC_POSITION", "SAVE_CONFIG", "RESTART", "FIRMWARE_RESTART", "STATUS", "HELP", "PID_CALIBRATE", "MPC_CALIBRATE", "BED_MESH_CALIBRATE", "BED_MESH_PROFILE", "BED_MESH_CLEAR", "BED_MESH_OUTPUT", "BED_MESH_MAP", "QUAD_GANTRY_LEVEL", "Z_TILT_ADJUST", "PROBE", "PROBE_CALIBRATE", "PROBE_ACCURACY", "Z_OFFSET_APPLY_PROBE", "Z_OFFSET_APPLY_ENDSTOP", "SET_GCODE_OFFSET", "SAVE_GCODE_STATE", "RESTORE_GCODE_STATE", "PAUSE", "RESUME", "CANCEL_PRINT", "CLEAR_PAUSE", "SDCARD_PRINT_FILE", "SDCARD_RESET_FILE", "EXCLUDE_OBJECT", "EXCLUDE_OBJECT_DEFINE", "EXCLUDE_OBJECT_START", "EXCLUDE_OBJECT_END", "SET_PRINT_STATS_INFO", "SET_IDLE_TIMEOUT", "SET_STEPPER_ENABLE", "SET_TMC_CURRENT", "SET_TMC_FIELD", "DUMP_TMC", "INIT_TMC", "ACTIVATE_EXTRUDER", "SET_EXTRUDER_ROTATION_DISTANCE", "SYNC_EXTRUDER_MOTION", "SET_RETRACTION", "GET_RETRACTION", "SET_INPUT_SHAPER", "SHAPER_CALIBRATE", "TEST_RESONANCES", "ACCELEROMETER_QUERY", "SET_LED", "SET_PIN", "SET_SERVO", "GET_POSITION", "QUERY_ENDSTOPS", "QUERY_PROBE", "FORCE_MOVE", "SET_DISPLAY_TEXT", "RUN_SHELL_COMMAND", "UPDATE_DELAYED_GCODE", "SET_GCODE_VARIABLE", "TURN_OFF_HEATERS", "MANUAL_PROBE", "ACCEPT", "ABORT", "TESTZ", "SCREWS_TILT_CALCULATE", "BED_TILT_CALIBRATE", "DELTA_CALIBRATE", "ENDSTOP_PHASE_CALIBRATE", "SET_DUAL_CARRIAGE", "SET_SKEW", "SKEW_PROFILE", "CALC_MEASURED_SKEW", "GET_CURRENT_SKEW", "SET_FILAMENT_SENSOR", "QUERY_FILAMENT_SENSOR", "SET_HEATER_PID", "EMERGENCY_STOP", "M486"]
)

#: Host-side commands understood by OctoPrint.
HOST_COMMANDS = frozenset({"@PAUSE", "@RESUME", "@CANCEL", "@ABORT"})


def is_known(code: str) -> bool:
    if code in KLIPPER_COMMANDS or code in HOST_COMMANDS:
        return True
    if code[:1] == "T" and code[1:].isdigit():
        return True
    if code[:1] in {"G", "M"}:
        number = code[1:].split(".", 1)[0]
        if number.isdigit():
            pool = _G if code[0] == "G" else _M
            return int(number) in pool
    return False


@dataclass(frozen=True)
class HeaterTarget:
    heater: str  # hotend | bed | chamber
    index: int
    target: float
    waits: bool


_HOTEND_CODES = {"M104": False, "M109": True}
_BED_CODES = {"M140": False, "M190": True}
_CHAMBER_CODES = {"M141": False, "M191": True}


def heater_targets(cmd: Command, active_tool: int = 0) -> list[HeaterTarget]:
    """Every heater setpoint a command asks for. Empty list if none."""
    code = cmd.code
    if code in _HOTEND_CODES:
        value = cmd.num("S", cmd.num("R"))
        if value is None:
            return []
        tool = int(cmd.num("T", active_tool) or 0)
        return [HeaterTarget("hotend", tool, value, _HOTEND_CODES[code])]
    if code in _BED_CODES:
        value = cmd.num("S", cmd.num("R"))
        return [] if value is None else [HeaterTarget("bed", 0, value, _BED_CODES[code])]
    if code in _CHAMBER_CODES:
        value = cmd.num("S", cmd.num("R"))
        return [] if value is None else [HeaterTarget("chamber", 0, value, _CHAMBER_CODES[code])]
    if code == "M303":  # PID autotune heats the heater to S
        value = cmd.num("S")
        if value is None:
            return []
        index = int(cmd.num("E", 0) or 0)
        heater = "bed" if index == -1 else "hotend"
        return [HeaterTarget(heater, max(index, 0), value, True)]
    if code in {"SET_HEATER_TEMPERATURE", "PID_CALIBRATE", "MPC_CALIBRATE"}:
        name = (cmd.str_param("HEATER") or "").lower()
        value = cmd.num("TARGET")
        if value is None:
            return []
        return [_klipper_heater(name, value, waits=code != "SET_HEATER_TEMPERATURE")]
    return []


def _klipper_heater(name: str, value: float, waits: bool) -> HeaterTarget:
    if name.startswith("extruder"):
        suffix = name[len("extruder") :]
        return HeaterTarget("hotend", int(suffix) if suffix.isdigit() else 0, value, waits)
    if name == "heater_bed":
        return HeaterTarget("bed", 0, value, waits)
    # Generic heaters (chambers, enclosures, ...) get the chamber limit: the lowest one.
    return HeaterTarget("chamber", 0, value, waits)
