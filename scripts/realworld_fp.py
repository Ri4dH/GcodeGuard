"""False-positive check on real slicer output downloaded from public GitHub repositories.

    python scripts/realworld_fp.py [--cache DIR]

The files belong to their authors and are not redistributed here; this script
downloads them (pinned to the repository's default branch) into a cache folder
and scans them with a permissive machine envelope, so only the *behavioural*
rules are being tested, not whether a part fits one particular printer.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from urllib import parse, request

from gcodeguard import Firewall, load_policy
from gcodeguard.model import Severity

ROOT = Path(__file__).resolve().parent.parent

# (repository, path, slicer, note)
FILES = [
    ("GeekDetour/BrickLayers", "sample_gcode/Sample_BrickLayersChallengeSimple_5walls.gcode", "PrusaSlicer 2.9", ""),
    ("harpua555/OpenFilamentSensor", "tools/cubewithironing.gcode", "OrcaSlicer 2.3", "ironing"),
    ("heyvye/DXU", "Calibration/XY_calibration.gcode", "Cura 2.3", "dual extruder"),
    ("IvanCodesDev/ForgeX", "contracts/validation/fixtures/cura-marlin.gcode", "Cura 5.10", "fixture"),
    ("IvanCodesDev/ForgeX", "contracts/validation/fixtures/orca-klipper.gcode", "OrcaSlicer 2.2", "fixture"),
    ("IvanCodesDev/ForgeX", "contracts/validation/fixtures/prusa-marlin.gcode", "PrusaSlicer 2.8", "fixture"),
    ("kageurufu/preprocess_cancellation", "GCode/m486.gcode", "PrusaSlicer 2.4", "arcs, Klipper"),
    ("kageurufu/preprocess_cancellation", "GCode/prusaslicer.gcode", "PrusaSlicer 2.4", "arcs, Klipper"),
    ("mriscoc/Ender3V2S1", "slicer scripts/prusa-superslicer/SimplePrusaTest.gcode", "PrusaSlicer 2.6", ""),
    ("notmahi/dobb-e", "hardware/robotClamp/hexnutBorder/hexnutBorder_prusaMK3S.gcode", "PrusaSlicer 2.6", ""),
    ("Obijuan/3D-parts", "Coletero-molly/coletero.gcode", "Cura 13.12", ""),
    ("Phil1988/FreeDi", "presliced_z-offset_calibration_files/Plus4/z-offset_calibration_Plus4_PLA_4m4s.gcode",
     "OrcaSlicer 2.2", "Qidi"),
    ("vgdh/OrcaSlicer-first-layer-travel-acceleration-fix", "example.gcode", "OrcaSlicer 2.1", "Klipper"),
    ("xreef/MKS_WIFI_upgrade_with_BeePrint_web_interface", "testSTL/FBG5_5mmCube.gcode", "Cura 4.12", ""),
    ("xyz-tools/gcode-preview", "demo/gcodes/vase.gcode", "PrusaSlicer 2.7", "spiral vase"),
]


def fetch(repo: str, path: str, cache: Path) -> Path:
    target = cache / (repo.replace("/", "__") + "__" + Path(path).name.replace(" ", "_"))
    if not target.exists():
        url = f"https://raw.githubusercontent.com/{repo}/HEAD/{parse.quote(path)}"
        req = request.Request(url, headers={"User-Agent": "gcodeguard-realworld-fp"})
        with request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https host)
            target.write_bytes(resp.read())
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "gcodeguard-realworld")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    policy = load_policy(str(ROOT / "examples" / "policies" / "large-machine.yaml"))
    print("| File | Slicer | Lines | Blocked | Warnings |")
    print("|---|---|---:|---:|---|")
    totals = {"files": 0, "blocked_files": 0, "warned_files": 0}
    for repo, path, slicer, note in FILES:
        try:
            file = fetch(repo, path, args.cache)
        except OSError as exc:
            print(f"| {repo}/{Path(path).name} | download failed: {exc} | | | |")
            continue
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        result = Firewall(policy).scan(lines)
        notable = [f for f in result.findings if f.severity is not Severity.INFO]
        blocked = sum(1 for d in result.decisions if d.blocked)
        rules = sorted({f.rule_id for f in notable})
        totals["files"] += 1
        totals["blocked_files"] += bool(blocked)
        totals["warned_files"] += bool(notable)
        name = f"[{Path(path).name}](https://github.com/{repo}/blob/HEAD/{parse.quote(path)})"
        label = slicer + (f" ({note})" if note else "")
        print(f"| {name} | {label} | {len(lines):,} | {blocked} | {', '.join(f'`{r}`' for r in rules) or '-'} |")
    print(f"\n{totals['files']} files: {totals['blocked_files']} with anything blocked, "
          f"{totals['warned_files']} with any warning.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
