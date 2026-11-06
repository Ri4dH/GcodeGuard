import pytest

from gcodeguard.gcode import parse_line


@pytest.mark.parametrize(
    ("line", "code", "params"),
    [
        ("G1 X10 Y-2.5 F3000", "G1", {"X": "10", "Y": "-2.5", "F": "3000"}),
        ("G01 X1", "G1", {"X": "1"}),
        ("g1x10y20", "G1", {"X": "10", "Y": "20"}),
        ("M104 S 300", "M104", {"S": "300"}),
        ("N12 M104 S300*45", "M104", {"S": "300"}),
        ("n4410 m104s285*97", "M104", {"S": "285"}),
        ("  M140 S60 ; bed", "M140", {"S": "60"}),
        ("G28 X Y", "G28", {"X": None, "Y": None}),
        ("G29.1 Z0", "G29.1", {"Z": "0"}),
        ("M104 (set temp) S200", "M104", {"S": "200"}),
        ("G1 X.5 E-.8", "G1", {"X": ".5", "E": "-.8"}),
        ("T1", "T1", {}),
    ],
)
def test_classic(line, code, params):
    cmd = parse_line(line)
    assert cmd.kind == "classic"
    assert cmd.code == code
    assert dict(cmd.params) == params


def test_comments_are_captured():
    cmd = parse_line("G28 ; home all axes")
    assert cmd.comment == "home all axes"
    assert parse_line("; just a comment").is_empty
    assert parse_line("").is_empty


def test_klipper_extended():
    cmd = parse_line("SET_HEATER_TEMPERATURE HEATER=extruder TARGET=210")
    assert cmd.kind == "extended"
    assert cmd.code == "SET_HEATER_TEMPERATURE"
    assert cmd.str_param("HEATER") == "extruder"
    assert cmd.num("TARGET") == 210


def test_macro_with_classic_prefix_is_extended():
    # A user macro called M104_SAFE must not be read as M104 with params "_SAFE".
    assert parse_line("M104_SAFE TEMP=200").code == "M104_SAFE"
    assert parse_line("GET_POSITION").code == "GET_POSITION"


def test_string_argument_commands():
    cmd = parse_line("M117 Hello world S300")
    assert cmd.code == "M117"
    assert cmd.text == "Hello world S300"
    assert cmd.params == {}
    assert parse_line("M28 auto0.g").text == "auto0.g"


def test_host_command():
    cmd = parse_line("@pause")
    assert cmd.kind == "host"
    assert cmd.code == "@PAUSE"


def test_num_handles_garbage():
    cmd = parse_line("SET_HEATER_TEMPERATURE HEATER=extruder TARGET=hot")
    assert cmd.num("TARGET") is None
    assert cmd.num("MISSING", 5.0) == 5.0


def test_with_params_rewrites_classic_and_extended():
    assert parse_line("M104 S300 T0").with_params({"S": "240"}).to_line() == "M104 S240 T0"
    ext = parse_line("SET_HEATER_TEMPERATURE HEATER=extruder TARGET=300")
    assert ext.with_params({"TARGET": "240"}).to_line() == (
        "SET_HEATER_TEMPERATURE HEATER=extruder TARGET=240"
    )
