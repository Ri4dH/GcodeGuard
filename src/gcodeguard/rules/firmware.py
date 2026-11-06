"""Firmware rules: persistent settings, calibration tampering, SD-card payloads."""

from __future__ import annotations

from collections.abc import Iterable

from gcodeguard.model import Category, Finding, Severity
from gcodeguard.rules.base import Context, Rule

_CALIBRATION = {
    "M92": "steps-per-mm (dimensional accuracy, extrusion amount)",
    "M301": "hotend PID tuning (temperature control stability)",
    "M304": "bed PID tuning (temperature control stability)",
    "M851": "probe Z offset (nozzle crashes into the bed)",
    "M665": "delta geometry",
    "M666": "endstop adjustments",
    "M425": "backlash compensation",
    "M913": "stepper hybrid threshold",
    "M914": "sensorless homing sensitivity",
    "SET_HEATER_PID": "heater PID tuning",
    "SET_EXTRUDER_ROTATION_DISTANCE": "extruder calibration (extrusion amount)",
    "M200": "volumetric extrusion / filament diameter",
}


class PersistSettings(Rule):
    id = "firmware.persist_settings"
    category = Category.FIRMWARE
    severity = Severity.CRITICAL
    summary = "Writes, resets, or replaces firmware configuration that survives reboots."

    _MESSAGES = {
        "M500": "M500 writes current settings to EEPROM: any tampered value survives power cycles",
        "M502": "M502 resets every setting to firmware defaults (wipes calibration)",
        "SAVE_CONFIG": "SAVE_CONFIG rewrites printer.cfg and restarts Klipper",
        "M997": "M997 starts a firmware update",
        "M504": "M504 validates EEPROM contents",
    }

    def check(self, ctx: Context) -> Iterable[Finding]:
        code = ctx.cmd.code
        if code in self._MESSAGES and code != "M504":
            yield self.hit(ctx, self._MESSAGES[code])


class CalibrationTamper(Rule):
    id = "firmware.calibration_tamper"
    category = Category.FIRMWARE
    severity = Severity.WARNING
    summary = "Changes calibration values (steps/mm, PID, probe offset, ...)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd = ctx.cmd
        what = _CALIBRATION.get(cmd.code)
        if what is None or (cmd.kind == "classic" and not cmd.params):
            return  # bare M92/M301 just report current values
        severity = Severity.CRITICAL if ctx.state.is_printing else None
        yield self.hit(ctx, f"{cmd.code} changes {what}", severity=severity)


class SdCard(Rule):
    id = "firmware.sd_card"
    category = Category.FIRMWARE
    severity = Severity.WARNING
    summary = "Writes files to, or starts prints from, the printer's SD card (bypasses the firewall)."

    def check(self, ctx: Context) -> Iterable[Finding]:
        cmd, firmware = ctx.cmd, ctx.policy.machine.firmware
        name = (cmd.text or "").strip()
        if cmd.code == "M28":
            boot = " (auto-run on boot!)" if name.lower().startswith("auto") else ""
            yield self.hit(ctx, f"M28 writes a file to the SD card: {name or '?'}{boot}",
                           severity=Severity.CRITICAL)
        elif cmd.code == "M30":
            yield self.hit(ctx, f"M30 deletes {name or 'a file'} from the SD card")
        elif cmd.code in {"M23", "M32", "M33"} and firmware != "klipper":
            # Inside a running print, starting a *different* file is never legitimate.
            severity = Severity.CRITICAL if ctx.state.is_printing else None
            yield self.hit(ctx, f"{cmd.code} starts a print from the SD card; that G-code never "
                                "passes through GcodeGuard", severity=severity)
        elif cmd.code == "M928":
            yield self.hit(ctx, "M928 starts logging commands to the SD card")
