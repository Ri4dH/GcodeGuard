"""OctoPrint plugin and Klipper module, tested against mocks of their host APIs."""

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest

from gcodeguard.integrations import klipper_extra

# --------------------------------------------------------------- OctoPrint


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    octoprint = types.ModuleType("octoprint")
    plugin_mod = types.ModuleType("octoprint.plugin")
    for name in ["StartupPlugin", "SettingsPlugin", "TemplatePlugin", "AssetPlugin",
                 "EventHandlerPlugin", "ShutdownPlugin"]:
        setattr(plugin_mod, name, type(name, (), {"on_settings_save": lambda self, data: None}))
    util = types.ModuleType("octoprint.util")
    util.RepeatedTimer = MagicMock()
    octoprint.plugin, octoprint.util = plugin_mod, util
    monkeypatch.setitem(sys.modules, "octoprint", octoprint)
    monkeypatch.setitem(sys.modules, "octoprint.plugin", plugin_mod)
    monkeypatch.setitem(sys.modules, "octoprint.util", util)
    sys.modules.pop("octoprint_gcodeguard", None)
    module = importlib.import_module("octoprint_gcodeguard")

    impl = module.GcodeGuardPlugin()
    settings = {"profile": "ender3", "policy_file": "", "strict": False, "mode": "enforce",
                "on_block": "pause", "scan_uploads": True, "watchdog_minutes": 10}
    impl._settings = MagicMock()
    impl._settings.get.side_effect = lambda path: settings[path[0]]
    impl._settings.get_boolean.side_effect = lambda path: bool(settings[path[0]])
    impl._printer = MagicMock()
    impl._printer.is_printing.return_value = False
    impl._plugin_manager = MagicMock()
    impl._logger = MagicMock()
    impl._identifier = "gcodeguard"
    impl.get_plugin_data_folder = lambda: str(tmp_path)
    impl._rebuild()
    impl.settings = settings
    impl.module = module
    return impl


def queue(plugin, cmd):
    return plugin.on_gcode_queuing(None, "queuing", cmd, None, cmd.split()[0])


def test_plugin_metadata(plugin):
    hooks = plugin.module.__plugin_hooks__
    assert "octoprint.comm.protocol.gcode.queuing" in hooks
    assert plugin.module.__plugin_pythoncompat__.startswith(">=3.10")


def test_plugin_allows_blocks_and_notifies(plugin):
    assert queue(plugin, "G28") is None
    assert queue(plugin, "M104 S300") == (None,)
    assert plugin.blocked == 1
    message = plugin._plugin_manager.send_plugin_message.call_args[0][1]
    assert message["type"] == "error" and "M104 S300" in message["text"]
    plugin._printer.pause_print.assert_not_called()  # not printing


def test_plugin_pauses_print_on_block(plugin):
    plugin._printer.is_printing.return_value = True
    assert queue(plugin, "M500") == (None,)
    plugin._printer.pause_print.assert_called_once()


def test_plugin_cancel_option(plugin):
    plugin.settings["on_block"] = "cancel"
    plugin._printer.is_printing.return_value = True
    queue(plugin, "M500")
    plugin._printer.cancel_print.assert_called_once()


def test_plugin_writes_audit_log(plugin, tmp_path):
    from gcodeguard.audit import verify

    queue(plugin, "M500")
    assert verify(tmp_path / "audit.jsonl").records == 1


def test_plugin_strict_mode(plugin):
    plugin.settings["strict"] = True
    plugin._rebuild()
    assert queue(plugin, "MYSTERY_MACRO") == (None,)


def test_plugin_bad_policy_falls_back(plugin, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("nope: 1")
    plugin.settings["policy_file"] = str(bad)
    plugin._rebuild()
    assert plugin._firewall.policy.name == "generic-fdm"


def test_plugin_watchdog(plugin):
    plugin._printer.is_operational.return_value = True
    plugin._printer.get_current_temperatures.return_value = {"tool0": {"target": 200}}
    plugin._watchdog_tick()
    plugin._printer.commands.assert_not_called()
    plugin._last_activity -= 11 * 60
    plugin._watchdog_tick()
    plugin._printer.commands.assert_called_once_with(["M104 S0", "M140 S0"])


def test_plugin_fails_closed(plugin, monkeypatch):
    def boom(line):
        raise RuntimeError("bug")

    monkeypatch.setattr(plugin._firewall, "check", boom)
    assert queue(plugin, "G28") == (None,)
    plugin._logger.exception.assert_called_once()


def test_plugin_print_started_resets_state(plugin):
    queue(plugin, "G28")
    plugin.on_event("PrintStarted", {})
    assert plugin._firewall.state.homed == set()


# ----------------------------------------------------------------- Klipper


class FakeGcode:
    def __init__(self):
        self.handlers = {}

    def register_command(self, name, func, desc=None):
        if func is None:
            return self.handlers.pop(name, None)
        self.handlers[name] = func
        return None

    def create_gcode_command(self, command, commandline, params):
        return FakeCmd(commandline, params)


class FakeCmd:
    class Error(Exception):
        pass

    def __init__(self, line, params=None):
        self.line, self.params, self.messages = line, params or {}, []

    def get_commandline(self):
        return self.line

    def respond_info(self, msg):
        self.messages.append(msg)

    def error(self, msg):
        return FakeCmd.Error(msg)


class FakeConfig:
    def __init__(self, printer, values):
        self.printer, self.values = printer, values

    def get_printer(self):
        return self.printer

    def get(self, key, default=None):
        return self.values.get(key, default)

    def getboolean(self, key, default=False):
        return self.values.get(key, default)

    def error(self, msg):
        return RuntimeError(msg)


@pytest.fixture
def klipper():
    gcode = FakeGcode()
    calls = []
    for name in ["M104", "SAVE_CONFIG", "G92", "SET_HEATER_TEMPERATURE"]:
        gcode.register_command(name, lambda gcmd, n=name: calls.append((n, gcmd)))
    events = {}
    printer = MagicMock()
    printer.lookup_object.side_effect = lambda name, default=None: gcode if name == "gcode" else default
    printer.register_event_handler.side_effect = lambda ev, fn: events.__setitem__(ev, fn)
    guard = klipper_extra.load_config(FakeConfig(printer, {"profile": "voron-350"}))
    events["klippy:connect"]()
    return guard, gcode, calls


def test_klipper_wraps_and_allows(klipper):
    guard, gcode, calls = klipper
    gcode.handlers["M104"](FakeCmd("M104 S250"))
    assert calls[-1][0] == "M104"
    assert "GCODEGUARD_STATUS" in gcode.handlers


def test_klipper_blocks_with_error(klipper):
    guard, gcode, calls = klipper
    with pytest.raises(FakeCmd.Error, match="GcodeGuard blocked SAVE_CONFIG"):
        gcode.handlers["SAVE_CONFIG"](FakeCmd("SAVE_CONFIG"))
    assert guard.blocked == 1 and not calls


def test_klipper_clamp_creates_new_command(klipper):
    from dataclasses import replace

    from gcodeguard.model import Action
    from gcodeguard.policy import RuleConfig

    guard, gcode, calls = klipper
    guard.firewall.policy = replace(guard.firewall.policy,
                                    rules={"thermal.heater_limit": RuleConfig(action=Action.CLAMP)})
    gcode.handlers["SET_HEATER_TEMPERATURE"](FakeCmd("SET_HEATER_TEMPERATURE HEATER=extruder TARGET=400"))
    name, new_cmd = calls[-1]
    assert new_cmd.params["TARGET"] == "290"


def test_klipper_missing_commands_are_skipped(klipper):
    _, gcode, _ = klipper
    assert "RUN_SHELL_COMMAND" not in gcode.handlers  # not configured on this printer
