"""OctoPrint plugin: filters every command OctoPrint sends to the printer.

Hooks ``octoprint.comm.protocol.gcode.queuing``, which sees every line, whether
it comes from a streamed file, the terminal, the REST API, or another plugin
(including AI-agent plugins). Blocked lines are suppressed; on a block during a
print the plugin can pause the job. Uploaded files are scanned in the
background, and a heater watchdog switches off heaters left idle.
"""

from __future__ import annotations

import os
import threading
import time

import octoprint.plugin
from octoprint.util import RepeatedTimer

from gcodeguard import __version__
from gcodeguard.audit import AuditLog
from gcodeguard.engine import Firewall
from gcodeguard.model import Severity
from gcodeguard.policy import PolicyError, builtin_profiles, load_policy

_PRINT_RESET_EVENTS = {"PrintStarted"}


class GcodeGuardPlugin(
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.EventHandlerPlugin,
    octoprint.plugin.ShutdownPlugin,
):
    def __init__(self) -> None:
        self._firewall: Firewall | None = None
        self._audit: AuditLog | None = None
        self._lock = threading.Lock()
        self._last_activity = time.monotonic()
        self._watchdog: RepeatedTimer | None = None
        self.blocked = 0

    # ------------------------------------------------------------ settings
    def get_settings_defaults(self):
        return {
            "profile": "generic-fdm",
            "policy_file": "",
            "strict": False,
            "mode": "enforce",
            "on_block": "pause",  # pause | cancel | continue
            "scan_uploads": True,
            "watchdog_minutes": 10,
        }

    def get_template_configs(self):
        return [{"type": "settings", "custom_bindings": False}]

    def is_template_autoescaped(self):
        return True

    def get_template_vars(self):
        return {"profiles": builtin_profiles(), "version": __version__}

    def get_assets(self):
        return {"js": ["js/gcodeguard.js"]}

    def on_settings_save(self, data):
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self._rebuild()

    # ------------------------------------------------------------- startup
    def on_after_startup(self):
        self._rebuild()
        self._watchdog = RepeatedTimer(30.0, self._watchdog_tick, daemon=True)
        self._watchdog.start()

    def on_shutdown(self):
        if self._watchdog is not None:
            self._watchdog.cancel()

    def _rebuild(self) -> None:
        refs = [self._settings.get(["profile"]) or "generic-fdm"]
        if self._settings.get_boolean(["strict"]):
            refs.append("agent-strict")
        policy_file = (self._settings.get(["policy_file"]) or "").strip()
        if policy_file:
            refs.append(policy_file)
        try:
            policy = load_policy(*refs)
        except PolicyError as exc:
            self._logger.error("GcodeGuard policy error, falling back to generic-fdm: %s", exc)
            self._notify("error", f"Policy error: {exc}. Using generic-fdm.")
            policy = load_policy("generic-fdm")
        if self._settings.get(["mode"]) == "monitor":
            from dataclasses import replace

            policy = replace(policy, mode="monitor")
        self._audit = AuditLog(os.path.join(self.get_plugin_data_folder(), "audit.jsonl"))
        with self._lock:
            self._firewall = Firewall(policy, audit=self._audit)
        self._logger.info("GcodeGuard %s active with policy %s (%s)", __version__, policy.name,
                          policy.mode)

    # ---------------------------------------------------------------- hook
    def on_gcode_queuing(self, comm_instance, phase, cmd, cmd_type, gcode, subcode=None, tags=None,
                         *args, **kwargs):
        firewall = self._firewall
        if firewall is None or not cmd:
            return None
        try:
            with self._lock:
                firewall.state.printing_override = self._printer.is_printing()
                decision = firewall.check(cmd)
        except Exception:  # fail closed: an unchecked command never reaches the printer
            self._logger.exception("GcodeGuard failed to check %r; blocking it", cmd)
            self._notify("error", f"Internal error while checking {cmd!r}; command blocked.")
            self.blocked += 1
            self._on_block()
            return (None,)
        self._last_activity = time.monotonic()
        notable = [f for f in decision.findings if f.severity is not Severity.INFO]
        if notable:
            self._logger.warning("GcodeGuard %s %r: %s", decision.action.value, cmd,
                                 "; ".join(f.message for f in notable))
            self._notify("error" if decision.blocked else "notice",
                         f"{decision.action.value.upper()}: {cmd} - {notable[0].message}")
        if decision.blocked:
            self.blocked += 1
            self._on_block()
            return (None,)
        if decision.rewritten:
            return decision.output
        return None

    def _on_block(self) -> None:
        if not self._printer.is_printing():
            return
        action = self._settings.get(["on_block"])
        if action == "pause":
            self._printer.pause_print()
        elif action == "cancel":
            self._printer.cancel_print()

    # -------------------------------------------------------------- events
    def on_event(self, event, payload):
        if event in _PRINT_RESET_EVENTS and self._firewall is not None:
            with self._lock:
                self._firewall.reset()
        elif event == "FileAdded" and self._settings.get_boolean(["scan_uploads"]):
            threading.Thread(target=self._scan_upload, args=(payload,), daemon=True).start()

    def _scan_upload(self, payload) -> None:
        if payload.get("storage") != "local" or not str(payload.get("path", "")).endswith(
            (".gcode", ".gco", ".g")
        ):
            return
        path = self._file_manager.path_on_disk("local", payload["path"])
        with open(path, encoding="utf-8", errors="replace") as fh:
            result = Firewall(self._firewall.policy).scan(fh.read().splitlines())
        if result.verdict in {"block", "warn"}:
            first = next((f for f in result.findings if f.severity is not Severity.INFO), None)
            detail = f" - line {first.line_no}: {first.message}" if first and first.line_no else ""
            self._notify("error" if result.verdict == "block" else "notice",
                         f"Scanned {payload['path']}: {result.verdict.upper()}{detail}")

    # ------------------------------------------------------------ watchdog
    def _watchdog_tick(self) -> None:
        minutes = float(self._settings.get(["watchdog_minutes"]) or 0)
        if minutes <= 0 or self._printer.is_printing() or not self._printer.is_operational():
            return
        temps = self._printer.get_current_temperatures() or {}
        hot = [k for k, v in temps.items() if (v or {}).get("target") and v["target"] > 50]
        if hot and time.monotonic() - self._last_activity > minutes * 60:
            self._printer.commands(["M104 S0", "M140 S0"])
            self._notify("notice", f"Heaters ({', '.join(hot)}) were idle for {minutes:g} min: "
                                   "switched off.")
            self._last_activity = time.monotonic()

    # --------------------------------------------------------------- utils
    def _notify(self, level: str, text: str) -> None:
        self._plugin_manager.send_plugin_message(self._identifier, {"type": level, "text": text})

    def get_update_information(self):
        return {
            "gcodeguard": {
                "displayName": "GcodeGuard",
                "displayVersion": self._plugin_version,
                "type": "github_release",
                "user": "Ri4dH",
                "repo": "PrintGuard",
                "current": self._plugin_version,
                "pip": "https://github.com/Ri4dH/PrintGuard/archive/{target_version}.zip",
            }
        }


__plugin_name__ = "GcodeGuard"
__plugin_version__ = __version__
__plugin_description__ = "Safety firewall: blocks dangerous, sabotaged, or AI-injected G-code."
__plugin_pythoncompat__ = ">=3.10,<4"
__plugin_implementation__ = GcodeGuardPlugin()
__plugin_hooks__ = {
    # High order value = runs after other plugins have rewritten the command.
    "octoprint.comm.protocol.gcode.queuing": (__plugin_implementation__.on_gcode_queuing, 10000),
    "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
}
