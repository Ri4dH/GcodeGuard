"""Regenerate the example G-code files in examples/gcode/ (deterministic)."""

from __future__ import annotations

from pathlib import Path

from gcodeguard.bench.corpus import ATTACKS, Tamper, generate, random_spec

OUT = Path(__file__).resolve().parent.parent / "examples" / "gcode"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    spec = random_spec(3)
    clean = generate(spec)
    (OUT / "cube.gcode").write_text("\n".join(clean) + "\n")

    # One file, several attacks: what a poisoned download from a model site could look like.
    layers = [i for i, line in enumerate(clean) if line.startswith(";LAYER:")]
    mid = len(layers) // 2
    tampered = generate(spec, Tamper(e_scale={i: 0.5 for i in range(mid + 4, mid + 8)}))
    layers = [i for i, line in enumerate(tampered) if line.startswith(";LAYER:")]
    tampered = (
        tampered[:12]
        + ["M92 E70 ; 'improved extruder calibration'", "M500"]
        + tampered[12 : layers[mid] + 1]
        + ["M104 S255 ; 'better layer adhesion'"]
        + tampered[layers[mid] + 1 :]
    )
    tampered = [line for line in tampered if line not in {"M104 S0", "M140 S0"}]
    (OUT / "tampered-cube.gcode").write_text("\n".join(tampered) + "\n")
    print(f"wrote {OUT / 'cube.gcode'} and {OUT / 'tampered-cube.gcode'} "
          f"({len(ATTACKS)} attack classes available in the benchmark)")


if __name__ == "__main__":
    main()
