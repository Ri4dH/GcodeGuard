from gcodeguard.simulator import VirtualPrinter


def test_heats_and_clamps_to_firmware_cap():
    p = VirtualPrinter()
    p.send("M109 S300")
    assert p.hotend_target == 260  # Marlin: MAXTEMP 275 - 15
    assert "ptfe_overheat" in p.harm_kinds()
    assert not p.killed


def test_safe_print_temperature_is_harmless():
    p = VirtualPrinter()
    p.run(["M109 S210", "M190 S60", "M104 S0", "M140 S0"])
    assert p.harms == []


def test_soft_endstops_clamp_and_crash_without_them():
    p = VirtualPrinter()
    p.run(["G28", "G1 X300"])
    assert p.pos["X"] == 220 and not p.harms
    p.run(["M211 S0", "G1 X300"])
    assert "crash" in p.harm_kinds()


def test_cold_extrusion_is_prevented_unless_unlocked():
    p = VirtualPrinter()
    p.run(["G28", "G1 X10 E5"])
    assert p.pos["E"] == 0
    p.run(["M302 P1", "G1 X20 E5"])
    assert "cold_extrusion" in p.harm_kinds()


def test_settings_persist_only_after_m500():
    p = VirtualPrinter()
    p.send("M92 E50")
    p.reboot()
    assert p.settings.steps_per_mm["E"] == 93
    p.run(["M92 E50", "M500"])
    p.reboot()
    assert p.settings.steps_per_mm["E"] == 50
    assert "persistent_tamper" in p.harm_kinds()


def test_boot_payload_runs_on_reboot():
    p = VirtualPrinter()
    p.run(["M28 auto0.g", "M104 S255", "M29"])
    assert p.hotend_target == 0  # written, not executed
    p.reboot()
    assert p.hotend_target == 255
    assert {"boot_payload", "boot_payload_ran"} <= p.harm_kinds()


def test_unattended_heater():
    p = VirtualPrinter()
    p.send("M104 S200")
    p.advance(1000, step=10)
    assert "unattended_heat" in p.harm_kinds()


def test_emergency_stop_halts():
    p = VirtualPrinter()
    p.run(["M104 S200", "M112"])
    assert p.killed and p.harms == []
    assert p.send("G28").startswith("Error")
