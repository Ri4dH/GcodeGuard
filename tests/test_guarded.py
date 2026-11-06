import json
from dataclasses import replace

from gcodeguard.backends.sim import SimBackend
from gcodeguard.bench.corpus import ATTACKS, build, generate, random_spec
from gcodeguard.guarded import GuardedPrinter
from gcodeguard.tools import BLOCK_NOTE, PrinterTools


def make(policy, files=None):
    backend = SimBackend(files=files or {})
    clock = {"t": 0.0}
    gp = GuardedPrinter(backend, policy, clock=lambda: clock["t"])
    return gp, backend, clock


def test_live_commands_are_filtered(ender3):
    gp, backend, _ = make(ender3)
    result = gp.send_gcode("G28\nM104 S300\nM140 S60")
    assert result.sent == ["G28", "M140 S60"]
    assert result.blocked[0][0] == "M104 S300"
    assert backend.printer.hotend_target == 0
    assert gp.events[-1]["event"] == "blocked"


def test_live_state_persists_between_calls(ender3):
    gp, _, _ = make(ender3)
    gp.send_gcode("G28")
    assert gp.send_gcode("G1 X500").blocked  # homed in the previous call


def test_gate_refuses_dangerous_file(ender3):
    gp, backend, _ = make(ender3, {"bad.gcode": "G28\nM104 S300\n"})
    result = gp.print_file("bad.gcode")
    assert not result.allowed
    assert backend.printed == []


def test_gate_refuses_sabotaged_file(ender3):
    attack = next(a for a in ATTACKS if a.id == "stealth-underextrude")
    content = "\n".join(build(attack, random_spec(2)))
    gp, backend, _ = make(ender3, {"hinge.gcode": content})
    result = gp.print_file("hinge.gcode")
    assert not result.allowed
    assert {f.rule_id for f in result.reasons} == {"sabotage.extrusion_anomaly"}
    assert backend.printed == []


def test_clean_file_prints_unchanged(ender3):
    content = "\n".join(generate(random_spec(4)))
    gp, backend, _ = make(ender3, {"cube.gcode": content})
    result = gp.print_file("cube.gcode")
    assert result.allowed and result.printed_as == "cube.gcode"
    assert backend.printed == ["cube.gcode"]


def test_file_needing_cooldown_prints_sanitised_copy(ender3):
    gp, backend, _ = make(ender3)
    result = gp.upload_and_print("warm.gcode", "M104 S200\nG28\n")
    assert result.allowed and result.printed_as == "gcodeguard-warm.gcode"
    assert "M104 S0" in backend.files["gcodeguard-warm.gcode"]


def test_monitor_mode_never_refuses(ender3):
    gp, backend, _ = make(replace(ender3, mode="monitor"), {"bad.gcode": "M104 S300\n"})
    assert gp.print_file("bad.gcode").allowed


def test_watchdog_turns_off_idle_heaters(ender3):
    gp, backend, clock = make(ender3)
    gp.send_gcode("M104 S200\nM140 S60")
    clock["t"] = 300
    assert gp.watchdog_tick() is None
    clock["t"] = 700
    assert "switched them off" in gp.watchdog_tick()
    assert backend.printer.hotend_target == 0 and backend.printer.bed_target == 0


def test_tools_explain_blocks(ender3):
    gp, _, _ = make(ender3)
    tools = PrinterTools(gp)
    out = json.loads(tools.send_gcode("M500"))
    assert out["blocked"][0]["command"] == "M500"
    assert out["note"] == BLOCK_NOTE
    assert json.loads(tools.set_temperature("nozzle", 200))["error"]
    assert json.loads(tools.read_file("../etc/passwd"))["error"]


def test_tool_schemas_are_strict(ender3):
    gp, _, _ = make(ender3)
    for spec in PrinterTools(gp).specs():
        schema = spec.anthropic()
        assert schema["strict"] is True
        assert schema["input_schema"]["additionalProperties"] is False
        assert set(schema["input_schema"]["required"]) == set(schema["input_schema"]["properties"])
