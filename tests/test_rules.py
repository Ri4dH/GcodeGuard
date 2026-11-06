import pytest

from gcodeguard import Firewall
from gcodeguard.model import Action, Severity

from .conftest import PRINTING_PRELUDE, rules_hit, run


@pytest.mark.parametrize(
    ("lines", "rule", "action"),
    [
        (["M104 S241"], "thermal.heater_limit", Action.BLOCK),
        (["M109 R260"], "thermal.heater_limit", Action.BLOCK),
        (["M140 S101"], "thermal.heater_limit", Action.BLOCK),
        (["M141 S80"], "thermal.heater_limit", Action.BLOCK),
        (["SET_HEATER_TEMPERATURE HEATER=extruder1 TARGET=300"], "thermal.heater_limit", Action.BLOCK),
        (["SET_HEATER_TEMPERATURE HEATER=chamber TARGET=90"], "thermal.heater_limit", Action.BLOCK),
        (["M303 E0 S280 C8"], "thermal.heater_limit", Action.BLOCK),
        (["M104 S200", "G4 S900"], "thermal.idle_heater", Action.BLOCK),
        (["M302 P1"], "thermal.cold_extrusion_unlock", Action.BLOCK),
        (["M302 S0"], "thermal.cold_extrusion_unlock", Action.BLOCK),
        (["G28", "G1 X260"], "motion.out_of_bounds", Action.BLOCK),
        (["G28", "G1 Z-5"], "motion.out_of_bounds", Action.BLOCK),
        (["G28", "G91", "G1 X150", "G1 X150"], "motion.out_of_bounds", Action.BLOCK),
        (["G28", "G20", "G1 X10"], "motion.out_of_bounds", Action.BLOCK),  # 254mm
        (["G1 X10 F20000"], "motion.feedrate_limit", Action.WARN),
        (["M203 X1000"], "motion.limits_tamper", Action.BLOCK),
        (["SET_VELOCITY_LIMIT VELOCITY=900"], "motion.limits_tamper", Action.BLOCK),
        (["SET_TMC_FIELD STEPPER=x FIELD=x VALUE=1"], "motion.limits_tamper", Action.BLOCK),
        (["M211 S0"], "motion.endstops_disabled", Action.BLOCK),
        (["M121"], "motion.endstops_disabled", Action.BLOCK),
        (["FORCE_MOVE STEPPER=stepper_x DISTANCE=500 VELOCITY=50"], "motion.endstops_disabled", Action.BLOCK),
        (["SET_KINEMATIC_POSITION Z=0"], "motion.position_override", Action.BLOCK),
        (["M500"], "firmware.persist_settings", Action.BLOCK),
        (["M502"], "firmware.persist_settings", Action.BLOCK),
        (["SAVE_CONFIG"], "firmware.persist_settings", Action.BLOCK),
        (["M997"], "firmware.persist_settings", Action.BLOCK),
        (["M92 E50"], "firmware.calibration_tamper", Action.WARN),
        (["M301 P1 I1 D1"], "firmware.calibration_tamper", Action.WARN),
        (["M28 auto0.g"], "firmware.sd_card", Action.BLOCK),
        (["M30 old.gco"], "firmware.sd_card", Action.WARN),
        (["RUN_SHELL_COMMAND CMD=hack"], "host.shell", Action.BLOCK),
        (["FIRMWARE_RESTART"], "host.restart", Action.WARN),
        (["MYSTERY_MACRO"], "policy.unknown_command", Action.WARN),
        (["M221 S50"], "sabotage.flow_override", Action.WARN),
        (["M220 S300"], "sabotage.flow_override", Action.WARN),
    ],
)
def test_rule_fires(ender3, lines, rule, action):
    decision = run(Firewall(ender3), *lines)
    assert rule in rules_hit(decision)
    assert decision.action is action


@pytest.mark.parametrize(
    "lines",
    [
        ["M104 S240"],
        ["M140 S100"],
        ["M104 S0"],
        ["M104 S200", "G4 S30"],
        ["G4 S900"],  # long dwell, but nothing is hot
        ["G1 X400"],  # not homed yet: position unknown
        ["G28", "G1 X221.5"],  # inside the 2mm margin
        ["G28", "G92 E0"],
        ["M92"],  # report only
        ["M302"],  # report only
        ["M211 S1"],
        ["M84 S120"],  # only sets the idle timeout
        ["PRINT_START BED=60 HOTEND=210"],
        ["M117 Printing M104 S999"],  # display text is not a command
        ["M112"],
        ["G1 X10 F12000"],
        ["M201 X500 Y500"],
        ["M221 S100"],
    ],
)
def test_benign_lines_are_clean(ender3, lines):
    decision = run(Firewall(ender3), *lines)
    assert not [f for f in decision.findings if f.severity is not Severity.INFO], decision.findings
    assert decision.action is Action.ALLOW


def test_mid_print_escalations(ender3):
    fw = Firewall(ender3)
    run(fw, *PRINTING_PRELUDE)
    assert fw.state.is_printing
    cases = {
        "G92 X5": "motion.position_override",
        "M84": "motion.steppers_disabled",
        "M92 E50": "firmware.calibration_tamper",
        "M221 S60": "sabotage.flow_override",
        "RESTART": "host.restart",
        "M23 other.gco": "firmware.sd_card",
    }
    for line, rule in cases.items():
        decision = fw.check(line)
        assert rule in rules_hit(decision), line
        assert decision.action is Action.BLOCK, line


def test_temperature_rules_mid_print(ender3):
    fw = Firewall(ender3)
    run(fw, *PRINTING_PRELUDE)
    drop = fw.check("M104 S180")
    assert "sabotage.temperature_drop" in rules_hit(drop)
    low = fw.check("M104 S150")
    assert "thermal.low_print_temp" in rules_hit(low)
    standby = fw.check("M104 T1 S120")  # idle tool standby temperature
    assert not rules_hit(standby)


def test_end_sequence_is_clean(ender3):
    fw = Firewall(ender3)
    run(fw, *PRINTING_PRELUDE)
    for line in ["M104 S0", "M140 S0", "M84 X Y E"]:
        assert fw.check(line).action is Action.ALLOW, line


def test_layer_gap(ender3):
    fw = Firewall(ender3)
    run(fw, *PRINTING_PRELUDE)
    fw.check("G1 Z1.5")
    decision = fw.check("G1 X100 Y50 E9")
    assert "sabotage.layer_gap" in rules_hit(decision)


def test_strict_profile_blocks_what_standard_warns(strict):
    for line in ["M92 E50", "MYSTERY_MACRO", "FIRMWARE_RESTART", "M30 old.gco"]:
        assert Firewall(strict).check(line).action is Action.BLOCK, line


def test_unknown_allowlisted_macro(ender3):
    assert Firewall(ender3).check("TIMELAPSE_TAKE_FRAME").action is Action.ALLOW


def test_idle_heater_at_end_of_stream(fw):
    result = fw.scan(["M104 S200", "M140 S60", "G28"])
    assert [f.rule_id for f in result.stream_findings] == ["thermal.idle_heater"]
    assert fw.scan(["M104 S200", "M104 S0"]).stream_findings == []
    assert fw.scan(["M104 S200", "G28", "END_PRINT"]).stream_findings == []
