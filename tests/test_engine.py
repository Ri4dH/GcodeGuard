from dataclasses import replace

from gcodeguard import Firewall
from gcodeguard.model import Action
from gcodeguard.policy import RuleConfig, load_policy

from .conftest import run


def test_clamp_rewrites_command_and_state(ender3):
    policy = replace(ender3, rules={"thermal.heater_limit": RuleConfig(action=Action.CLAMP)})
    fw = Firewall(policy)
    decision = fw.check("M104 S300")
    assert decision.action is Action.CLAMP
    assert decision.output == "M104 S240"
    assert fw.state.hotend_target[0] == 240
    ext = fw.check("SET_HEATER_TEMPERATURE HEATER=extruder TARGET=999")
    assert ext.output == "SET_HEATER_TEMPERATURE HEATER=extruder TARGET=240"


def test_feedrate_clamp(ender3):
    policy = replace(ender3, rules={"motion.feedrate_limit": RuleConfig(action=Action.CLAMP)})
    decision = Firewall(policy).check("G1 X10 F99999")
    assert decision.output == "G1 X10 F12000"


def test_clamp_without_value_becomes_block(ender3):
    policy = replace(ender3, rules={"firmware.persist_settings": RuleConfig(action=Action.CLAMP)})
    assert Firewall(policy).check("M500").action is Action.BLOCK


def test_monitor_mode_never_blocks(ender3):
    fw = Firewall(replace(ender3, mode="monitor"))
    decision = fw.check("M104 S300")
    assert decision.action is Action.WARN
    assert decision.would_block
    assert decision.output == "M104 S300"
    assert fw.state.hotend_target[0] == 300  # it was forwarded


def test_blocked_commands_do_not_change_state(fw):
    run(fw, "G28", "M211 S0")
    assert fw.state.software_endstops is True
    fw.check("M104 S999")
    assert fw.state.hotend_target == {}


def test_emergency_stop_is_never_blocked():
    policy = load_policy("generic-fdm", "agent-strict")
    blocking = replace(policy, commands=replace(policy.commands, block=frozenset({"M112"})))
    for code in ["M112", "M108", "M410", "CANCEL_PRINT", "TURN_OFF_HEATERS", "@pause"]:
        assert Firewall(blocking).check(code).action is Action.ALLOW, code


def test_policy_block_list(ender3):
    policy = replace(ender3, commands=replace(ender3.commands, block=frozenset({"M600"})))
    assert Firewall(policy).check("M600").action is Action.BLOCK


def test_disabled_rule_is_skipped(ender3):
    policy = replace(ender3, rules={"thermal.heater_limit": RuleConfig(enabled=False)})
    assert Firewall(policy).check("M104 S300").action is Action.ALLOW


def test_filter_comments_out_blocked_and_adds_cooldown(fw):
    out = [text for text, _ in fw.filter(["M104 S200", "M500", "G4 S5"])]
    assert out[0] == "M104 S200"
    assert out[1].startswith("; GCODEGUARD BLOCKED: M500")
    assert out[-1].startswith("M104 S0 T0")


def test_filter_without_epilogue(fw):
    out = [text for text, _ in fw.filter(["M104 S200"], epilogue=False)]
    assert out == ["M104 S200"]


def test_scan_resets_state(fw):
    fw.scan(["G28", "M104 S200"])
    result = fw.scan(["G1 X999"])
    assert result.verdict == "pass"  # not homed in the second file


def test_scan_result_serialises(fw):
    data = fw.scan(["M104 S300", "M221 S50"]).to_dict()
    assert data["verdict"] == "block"
    assert data["actions"]["block"] == 1
    assert {d["findings"][0]["rule"] for d in data["decisions"]} == {
        "thermal.heater_limit", "sabotage.flow_override"}


def test_audit_sink_receives_decisions(ender3):
    events = []

    class Sink:
        def record(self, event, payload):
            events.append((event, payload))

    fw = Firewall(ender3, audit=Sink())
    fw.check("G28")
    fw.check("M500")
    assert [e for e, _ in events] == ["decision"]
    assert events[0][1]["action"] == "block"
