# Contributing

Thanks for helping make printers safer. Bug reports with a G-code sample are the most useful
contribution of all.

## Setup

```bash
git clone https://github.com/Ri4dH/PrintGuard && cd PrintGuard
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,media]"
pytest && ruff check src tests scripts
```

## Where things live

| Path | What |
|---|---|
| `src/gcodeguard/gcode.py` | Parser (must stay at least as lenient as firmware) |
| `src/gcodeguard/state.py` | Machine state: positions, heaters, extrusion |
| `src/gcodeguard/rules/` | One file per rule family. Add rules to `rules/__init__.py` |
| `src/gcodeguard/engine.py` | Rule evaluation and policy resolution |
| `src/gcodeguard/profiles/` | Built-in machine profiles (YAML) |
| `src/gcodeguard/simulator.py` | Virtual printer used for physical-outcome tests |
| `src/gcodeguard/bench/` | Attack corpus and prompt-injection scenarios |
| `src/octoprint_gcodeguard/`, `src/gcodeguard/integrations/` | OctoPrint and Klipper |

## Adding a rule

1. Write the rule (subclass `Rule`, set `id`, `category`, `severity`, `summary`).
2. Add positive *and* benign cases to `tests/test_rules.py`.
3. If it models a new attack, add it to `bench/corpus.py` and teach the simulator what harm looks
   like, so the benchmark measures outcomes and not just rule hits.
4. Run `python scripts/realworld_fp.py` and make sure real slicer files stay clean.

## Adding a machine profile

Copy the closest file in `src/gcodeguard/profiles/` and use `extends: generic-fdm`. Cite where
the limits come from (vendor docs, firmware config) in the `description`. Hotend limits should
reflect the *hardware* (PTFE liner, thermistor type), not just what the firmware allows.

## Pull requests

Keep them focused, with tests. Run `python scripts/make_examples.py` if you change the generator,
and `python scripts/media/make_media.py` if a change affects the README visuals.
