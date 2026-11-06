import pytest

from gcodeguard import Firewall
from gcodeguard.bench.corpus import ATTACKS, build, generate, random_spec
from gcodeguard.bench.runner import render_markdown, run_corpus
from gcodeguard.model import Severity

SEEDS = (1, 2, 3, 4, 5, 6)


@pytest.mark.parametrize("seed", SEEDS)
def test_benign_generated_prints_are_clean(ender3, seed):
    result = Firewall(ender3).scan(generate(random_spec(seed)))
    assert [f for f in result.findings if f.severity is not Severity.INFO] == []


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_every_attack_is_detected(ender3, attack):
    for seed in SEEDS[:3]:
        result = Firewall(ender3).scan(build(attack, random_spec(seed)))
        assert attack.expected_rules & {f.rule_id for f in result.findings}, (attack.id, seed)


def test_generator_is_deterministic():
    assert generate(random_spec(9)) == generate(random_spec(9))


def test_corpus_runner_small(ender3):
    report = run_corpus(ender3, seeds=range(1, 3), attacks=ATTACKS[:3])
    data = report.to_dict()
    assert data["benign"]["false_positive_block_rate"] == 0
    for row in data["attacks"]:
        assert row["detection_rate"] == 1 and row["harm_rate_with_gcodeguard"] == 0
        assert row["harm_rate_firmware_only"] == 1
    assert "| `overheat` | thermal | 100% | 100% | 0% | 0% |" in render_markdown(report)
