import math

import pytest

from gcodeguard.gcode import parse_line
from gcodeguard.state import MachineState


def feed(state, *lines):
    motion = None
    for line in lines:
        cmd = parse_line(line)
        motion = state.project(cmd)
        state.apply(cmd, motion)
    return motion


def test_relative_and_absolute_moves():
    s = MachineState()
    feed(s, "G28", "G1 X10 Y10", "G91", "G1 X5")
    assert s.position["X"] == 15
    feed(s, "G90", "G1 X1")
    assert s.position["X"] == 1


def test_extruder_modes():
    s = MachineState()
    feed(s, "M83", "G1 E1", "G1 E1")
    assert s.position["E"] == 2
    feed(s, "M82", "G1 E10")
    assert s.position["E"] == 10


def test_g92_offsets_track_physical_position():
    s = MachineState()
    feed(s, "G28", "G1 X100")
    feed(s, "G92 X0")
    motion = s.project(parse_line("G1 X50"))
    assert motion.physical["X"] == pytest.approx(150)


def test_inches():
    s = MachineState()
    motion = feed(s, "G20", "G1 X1")
    assert motion.target["X"] == pytest.approx(25.4)


def test_dwell_advances_clock():
    s = MachineState()
    feed(s, "G4 P1500", "G4 S2")
    assert s.clock_s == pytest.approx(3.5)


def test_printing_detection_and_end():
    s = MachineState()
    feed(s, "M104 S200", "G1 X10", "G1 X60 E6")
    assert s.printing and s.print_temp == 200
    feed(s, "M104 S0")
    assert not s.printing


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("G3 X0 Y10 I0 J5", math.pi * 5),  # half circle CCW from (0,0) around (0,5)
        ("G2 X0 Y10 I0 J5", math.pi * 5),  # half circle CW
        ("G2 X0 Y0 I5 J0", 2 * math.pi * 5),  # full circle
        ("G2 X10 Y0 R5", math.pi * 5),
        ("G2 X10 Y0 R-5", math.pi * 5),  # R<0 = the long way; same for a half circle
    ],
)
def test_arc_length(line, expected):
    s = MachineState()
    motion = s.project(parse_line(line))
    assert motion.distance_xy == pytest.approx(expected, rel=1e-6)


def test_quarter_arc_direction_matters():
    s = MachineState()
    s.position.update(X=5.0, Y=0.0)
    ccw = s.project(parse_line("G3 X0 Y5 I-5 J0"))
    cw = s.project(parse_line("G2 X0 Y5 I-5 J0"))
    assert ccw.distance_xy == pytest.approx(math.pi * 5 / 2)
    assert cw.distance_xy == pytest.approx(3 * math.pi * 5 / 2)
