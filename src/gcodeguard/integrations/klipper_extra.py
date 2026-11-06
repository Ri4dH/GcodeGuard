"""Klipper extras module: guards risky commands inside Klipper itself.

Install (in Klipper's Python environment)::

    ~/klippy-env/bin/pip install gcodeguard
    ln -s "$(~/klippy-env/bin/gcodeguard klipper-path)" ~/klipper/klippy/extras/gcode_guard.py

Then add to printer.cfg::

    [gcode_guard]
    profile: voron-350        # any built-in profile
    # policy: ~/printer_data/config/gcodeguard.yaml
    # strict: True            # recommended if an AI agent drives this printer
    # mode: monitor           # log only

Every command in ``GUARDED`` is re-registered with a wrapper that asks the
firewall first. Because the wrapper sits inside Klipper's G-code dispatcher, it
also sees commands issued by macros, Moonraker, Mainsail/Fluidd consoles,
virtual-SD prints, and agent tools. Klipper already enforces position limits and
heater max_temp from printer.cfg; this adds the rest (per-material temperature
caps, config persistence, shell escapes, mid-print tampering, ...).
"""

from __future__ import annotations

GUARDED = (
    "M104", "M109", "M140", "M190", "M141", "M191", "M303",
    "SET_HEATER_TEMPERATURE", "PID_CALIBRATE", "MPC_CALIBRATE", "SET_HEATER_PID",
    "SAVE_CONFIG", "FIRMWARE_RESTART", "RESTART", "RUN_SHELL_COMMAND",
    "SET_VELOCITY_LIMIT", "SET_KINEMATIC_POSITION", "FORCE_MOVE", "SET_TMC_CURRENT",
    "SET_TMC_FIELD", "SET_STEPPER_ENABLE", "M84", "M18", "G92", "M220", "M221",
    "SET_GCODE_OFFSET", "SET_EXTRUDER_ROTATION_DISTANCE", "M302", "M201", "M203", "M204", "G4",
)


class GcodeGuard:
    def __init__(self, config) -> None:
        self.printer = config.get_printer()
        try:
            from dataclasses import replace

            from gcodeguard import Firewall, PolicyError, load_policy
        except ImportError as exc:
            raise config.error(f"gcode_guard: install gcodeguard into klippy-env ({exc})") from exc
        refs = [config.get("profile", "generic-fdm")]
        if config.getboolean("strict", False):
            refs.append("agent-strict")
        policy_path = config.get("policy", None)
        if policy_path:
            refs.append(policy_path)
        try:
            policy = load_policy(*refs)
        except PolicyError as exc:
            raise config.error(f"gcode_guard: {exc}") from exc
        if config.get("mode", "enforce") == "monitor":
            policy = replace(policy, mode="monitor")
        self.firewall = Firewall(policy)
        self.blocked = 0
        self.gcode = self.printer.lookup_object("gcode")
        self.printer.register_event_handler("klippy:connect", self._wrap_commands)
        self.gcode.register_command("GCODEGUARD_STATUS", self.cmd_GCODEGUARD_STATUS,
                                    desc="Show GcodeGuard policy and block count")

    def _wrap_commands(self) -> None:
        for name in GUARDED:
            original = self.gcode.register_command(name, None)
            if original is None:
                continue
            self.gcode.register_command(name, self._wrapper(name, original),
                                        desc=f"{name} (checked by GcodeGuard)")

    def _printing(self) -> bool | None:
        stats = self.printer.lookup_object("print_stats", None)
        if stats is None:
            return None
        now = self.printer.get_reactor().monotonic()
        return stats.get_status(now).get("state") == "printing"

    def _wrapper(self, name, original):
        from gcodeguard.gcode import parse_line
        from gcodeguard.model import Severity

        def handler(gcmd) -> None:
            self.firewall.state.printing_override = self._printing()
            decision = self.firewall.check(gcmd.get_commandline())
            for finding in decision.findings:
                if finding.severity is not Severity.INFO:
                    gcmd.respond_info(f"GcodeGuard {decision.action.value}: {finding.message}")
            if decision.blocked:
                self.blocked += 1
                reasons = "; ".join(f.message for f in decision.findings)
                raise gcmd.error(f"GcodeGuard blocked {name}: {reasons}")
            if decision.rewritten and decision.output:
                cmd = parse_line(decision.output)
                params = {k: v for k, v in cmd.params.items() if v is not None}
                original(self.gcode.create_gcode_command(name, decision.output, params))
                return
            original(gcmd)

        return handler

    def cmd_GCODEGUARD_STATUS(self, gcmd) -> None:
        policy = self.firewall.policy
        gcmd.respond_info(f"GcodeGuard policy={policy.name} mode={policy.mode} "
                          f"blocked={self.blocked}")


def load_config(config):
    return GcodeGuard(config)
