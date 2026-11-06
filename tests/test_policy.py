import pytest

from gcodeguard.model import Action, Severity
from gcodeguard.policy import PolicyError, builtin_profiles, load_policy, merge


def test_builtin_profiles_load():
    names = builtin_profiles()
    assert {"generic-fdm", "ender3", "prusa-mk4", "voron-350", "agent-strict"} <= set(names)
    for name in names:
        load_policy("generic-fdm", name)


def test_extends_overrides_parent():
    policy = load_policy("ender3")
    assert policy.machine.max_hotend_temp == 240
    assert policy.machine.min_print_temp == 170  # inherited
    assert "PRINT_START" in policy.commands.allow


def test_overlay_unions_command_lists_and_escalates():
    policy = load_policy("voron-350", "agent-strict")
    assert "QUAD_GANTRY_LEVEL" in policy.commands.allow
    assert policy.commands.unknown is Action.BLOCK
    assert policy.rule("firmware.calibration_tamper").severity is Severity.CRITICAL
    assert policy.name == "voron-350 + agent-strict"


def test_merge_is_deep_and_non_destructive():
    base = {"machine": {"max_bed_temp": 100, "nozzle_diameter": 0.4}, "commands": {"allow": ["A"]}}
    out = merge(base, {"machine": {"max_bed_temp": 90}, "commands": {"allow": ["B"]}})
    assert out == {"machine": {"max_bed_temp": 90, "nozzle_diameter": 0.4}, "commands": {"allow": ["A", "B"]}}
    assert base["machine"]["max_bed_temp"] == 100


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("machine: {max_hotend_tmp: 200}", "unknown key"),
        ("machine: {max_hotend_temp: hot}", "expected a number"),
        ("machine: {max_hotend_temp: -5}", "must be >= 0"),
        ("machine: {build_volume: {x: [200, 0]}}", "greater than high"),
        ("machine: {build_volume: {w: [0, 1]}}", "unknown key"),
        ("machine: {firmware: grbl}", "unsupported firmware"),
        ("mode: yolo", "mode"),
        ("rules: {thermal.nope: false}", "unknown rule"),
        ("rules: {thermal.heater_limit: {action: explode}}", "is not one of"),
        ("commands: {unknown: clamp}", "makes no sense"),
        ("commands: {allow: G28}", "list of command names"),
        ("- just\n- a list", "must be a mapping"),
        ("machine: [1, 2", "invalid YAML"),
    ],
)
def test_validation_errors(tmp_path, text, message):
    path = _write(tmp_path, "p.yaml", text)
    with pytest.raises(PolicyError, match=message):
        load_policy(str(path))


def test_rule_can_be_disabled(tmp_path):
    path = _write(tmp_path, "p.yaml", "extends: generic-fdm\nrules: {sabotage.extrusion_anomaly: false}")
    assert load_policy(str(path)).rule("sabotage.extrusion_anomaly").enabled is False


def test_relative_extends_and_cycles(tmp_path):
    _write(tmp_path, "a.yaml", "extends: b.yaml\nname: a")
    _write(tmp_path, "b.yaml", "extends: a.yaml\nname: b")
    with pytest.raises(PolicyError, match="cycle"):
        load_policy(str(tmp_path / "a.yaml"))
    _write(tmp_path, "c.yaml", "extends: ender3\nname: c\nmachine: {max_bed_temp: 80}")
    _write(tmp_path, "d.yaml", "extends: c.yaml\nname: d")
    policy = load_policy(str(tmp_path / "d.yaml"))
    assert policy.machine.max_bed_temp == 80 and policy.machine.max_hotend_temp == 240


@pytest.mark.parametrize("name", ["../../etc/passwd", "Ender3", "a" * 80, "x;y"])
def test_builtin_names_cannot_escape_package(name):
    with pytest.raises(PolicyError):
        load_policy(name)


def test_missing_file():
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy("/nonexistent/policy.yaml")
