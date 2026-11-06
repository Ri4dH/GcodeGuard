import json
from pathlib import Path

import pytest

from gcodeguard.cli import main


@pytest.fixture
def gfile(tmp_path):
    def make(text, name="part.gcode"):
        path = tmp_path / name
        path.write_text(text)
        return str(path)

    return make


def test_scan_clean_file(gfile, capsys):
    assert main(["scan", gfile("G28\nM104 S200\nM104 S0\n"), "-p", "ender3"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_scan_blocked_file_exit_code(gfile):
    path = gfile("M104 S300\n")
    assert main(["scan", path, "-p", "ender3"]) == 2
    assert main(["scan", path, "-p", "ender3", "--fail-on", "never"]) == 0


def test_scan_warn_exit_code(gfile):
    path = gfile("M221 S50\n")
    assert main(["scan", path]) == 0
    assert main(["scan", path, "--fail-on", "warn"]) == 1


def test_scan_json_and_sarif(gfile, capsys):
    path = gfile("M104 S300\n")
    main(["scan", path, "-p", "ender3", "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data[path]["verdict"] == "block"
    main(["scan", path, "-p", "ender3", "-f", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "thermal.heater_limit" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_monitor_flag(gfile, capsys):
    main(["scan", gfile("M104 S300\n"), "-p", "ender3", "--monitor", "--fail-on", "never"])
    assert "WOULD-BLOCK" in capsys.readouterr().out


def test_sanitize_in_place(gfile, capsys):
    path = gfile("G28\nM500\nM104 S200\n")
    assert main(["sanitize", path, "--in-place"]) == 0
    text = Path(path).read_text()
    assert "; GCODEGUARD BLOCKED: M500" in text
    assert text.rstrip().endswith("cooling down")
    assert main(["sanitize", path, "--fail-on-block"]) == 0  # already sanitised
    assert main(["sanitize", gfile("M500\n", "b.gcode"), "--fail-on-block", "-o", "-"]) == 2


def test_simulate(gfile, capsys):
    path = gfile("M109 S255\nM104 S0\n")
    assert main(["simulate", path, "-p", "ender3", "--no-firewall"]) == 2
    assert "ptfe_overheat" in capsys.readouterr().out
    assert main(["simulate", path, "-p", "ender3"]) == 0


def test_profiles_rules_and_policy_errors(capsys, tmp_path):
    assert main(["profiles"]) == 0
    assert "ender3" in capsys.readouterr().out
    assert main(["rules"]) == 0
    assert "thermal.heater_limit" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("machine: {oops: 1}")
    assert main(["scan", str(bad), "--policy", str(bad)]) == 3


def test_audit_verify(tmp_path, capsys):
    from gcodeguard.audit import AuditLog

    log = tmp_path / "a.jsonl"
    AuditLog(log).record("x", {})
    assert main(["audit", "verify", str(log)]) == 0
    log.write_text(log.read_text().replace('"x"', '"y"'))
    assert main(["audit", "verify", str(log)]) == 2


def test_missing_file():
    with pytest.raises(SystemExit):
        main(["scan", "/nope.gcode"])
