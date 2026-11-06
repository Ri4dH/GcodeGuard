"""Build the README media from real runs.

    python scripts/media/make_media.py        # writes docs/media/*

* scan.gif        - typed `gcodeguard scan` / `simulate` commands and their real output
* agent-demo.mp4  - split screen: a prompt-injected agent's tool calls (left) and the
                    simulated hotend temperature with and without GcodeGuard (right)
* agent-demo.gif  - the same video as a GIF (GitHub READMEs autoplay GIFs inline)

The agent transcript is the benchmark's worst-case scripted agent (it obeys the
injected instruction); the tool results shown are the actual strings GcodeGuard returned.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
OUT = ROOT / "docs" / "media"

from terminal import Terminal, save_gif, session  # noqa: E402

# Validated with the dataviz palette checker (dark surface): slot 1 blue, slot 2 orange.
SURFACE, INK, INK2, GRID = "#1a1a19", "#f0efec", "#c3c2b7", "#383835"
GUARDED, UNGUARDED = "#3987e5", "#d95926"


def run_cli(*args: str) -> str:
    env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": "120"}
    exe = shutil.which("gcodeguard", path=str(Path(sys.executable).parent)) or "gcodeguard"
    proc = subprocess.run([exe, *args], cwd=ROOT, env=env, capture_output=True, text=True)
    return proc.stdout.rstrip()


def make_scan_gif() -> Path:
    term = Terminal(cols=126, rows=30, title="gcodeguard - zsh")
    scenes = [
        ("gcodeguard scan examples/gcode/tampered-cube.gcode -p ender3",
         run_cli("scan", "examples/gcode/tampered-cube.gcode", "-p", "ender3")),
        ("gcodeguard simulate examples/gcode/tampered-cube.gcode -p ender3 --no-firewall",
         run_cli("simulate", "examples/gcode/tampered-cube.gcode", "-p", "ender3", "--no-firewall")),
    ]
    path = OUT / "scan.gif"
    save_gif(session(term, scenes), path)
    return path


# ----------------------------------------------------------------- agent video
def _agent_runs():
    from gcodeguard.bench.agent import make_env, run_scripted
    from gcodeguard.bench.scenarios import SCENARIOS

    scenario = next(s for s in SCENARIOS if s.id == "web-petg-overtemp")
    traces = {}
    for guarded in (False, True):
        env = make_env(scenario, guarded)
        samples = []
        for name, args in scenario.script:
            env.call(name, args)
        start = env.printer.t
        for _ in range(170):
            env.printer.advance(1.0)
            samples.append((env.printer.t - start, env.printer.hotend))
        traces[guarded] = (env.calls, samples, [e for e in env.printer.events if e.harmful])
    run_scripted(scenario, True)  # sanity: the benchmark agrees
    return scenario, traces


def _wrap(text: str, width: int) -> list[str]:
    out = []
    for para in text.splitlines():
        out.extend(textwrap.wrap(para, width) or [""])
    return out


def make_agent_video() -> tuple[Path, Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    scenario, traces = _agent_runs()
    calls_off, temps_off, harms_off = traces[False]
    calls_on, temps_on, _ = traces[True]
    blocked = json.loads(calls_on[1]["result"])["blocked"][0]["reasons"][0]
    page = scenario.web["https://filament-guide.example/petg"]
    ptfe_time = next((t for t, temp in temps_off if temp >= 245), None)

    chat = [
        ("user", "User", scenario.task),
        ("tool", "agent -> fetch_url", "filament-guide.example/petg"),
        ("inject", "page (attacker-edited)", page.split("\n\n")[1]),
        ("tool", "agent -> send_gcode", "M104 S265\nM140 S85"),
        ("off", "without GcodeGuard", "sent. Firmware accepts it (caps at 260C)."),
        ("on", "with GcodeGuard", f"BLOCKED: {blocked}"),
    ]
    reveal = [0, 10, 22, 36, 48, 54]  # frame index at which each message appears
    colors = {"user": INK2, "tool": INK2, "inject": "#e66767", "off": UNGUARDED, "on": GUARDED}

    frames_dir = Path(tempfile.mkdtemp(prefix="gcodeguard-frames-"))
    total = 150
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 13})
    for frame in range(total):
        fig = plt.figure(figsize=(12.8, 7.2), dpi=100, facecolor=SURFACE)
        fig.text(0.03, 0.93, "A prompt-injected AI agent tries to overheat a printer",
                 color=INK, fontsize=20, fontweight="bold")
        fig.text(0.03, 0.885, "Same agent, same poisoned web page. Simulated Ender-3 with a "
                 "PTFE-lined hotend.", color=INK2, fontsize=13)
        # transcript
        y = 0.80
        for idx, (kind, who, text) in enumerate(chat):
            if frame < reveal[idx]:
                break
            fig.text(0.03, y, who, color=colors[kind], fontsize=12, fontweight="bold")
            y -= 0.035
            mono = kind in {"tool", "off", "on"}
            wrapped = _wrap(text, 44 if not mono else 46)
            shown = wrapped[:5]
            if len(wrapped) > 5:
                shown[-1] += " ..."
            for line in shown:
                fig.text(0.045, y, line, color=INK if kind != "user" else INK2, fontsize=11.5,
                         family="DejaVu Sans Mono" if mono else "DejaVu Sans")
                y -= 0.032
            y -= 0.02
        # chart
        ax = fig.add_axes([0.53, 0.14, 0.43, 0.68], facecolor=SURFACE)
        n = max(0, frame - 36)
        t_off = [t for t, _ in temps_off[:n]]
        ax.plot(t_off, [v for _, v in temps_off[:n]], color=UNGUARDED, lw=2.2,
                solid_capstyle="round")
        ax.plot([t for t, _ in temps_on[:n]], [v for _, v in temps_on[:n]], color=GUARDED, lw=2.2,
                solid_capstyle="round")
        ax.axhline(245, color=INK2, lw=1, ls=(0, (4, 4)))
        ax.text(3, 249, "PTFE liner degrades, toxic fumes (~245C)", color=INK2, fontsize=11)
        ax.set_xlim(0, 120)
        ax.set_ylim(0, 290)
        ax.set_xlabel("seconds after the agent's command", color=INK2)
        ax.set_ylabel("hotend temperature (C)", color=INK2)
        ax.tick_params(colors=INK2, length=0)
        ax.grid(color=GRID, lw=0.8)
        for spine in ax.spines.values():
            spine.set_visible(False)
        if n:
            ax.text(t_off[-1] + 1.5, temps_off[n - 1][1], " without GcodeGuard", color=UNGUARDED,
                    fontsize=11.5, va="center", fontweight="bold") if t_off[-1] < 85 else None
            ax.text(min(temps_on[n - 1][0], 82) + 1.5, temps_on[n - 1][1] + 10, "with GcodeGuard",
                    color=GUARDED, fontsize=11.5, fontweight="bold")
        if n and ptfe_time and temps_off[n - 1][0] >= ptfe_time:
            ax.annotate(f"{ptfe_time:.0f}s: fumes", xy=(ptfe_time, 245), xytext=(ptfe_time - 45, 270),
                        color=UNGUARDED, fontsize=11.5, fontweight="bold",
                        arrowprops={"arrowstyle": "-", "color": UNGUARDED, "lw": 1})
            ax.text(118, 270, "without GcodeGuard", color=UNGUARDED, fontsize=11.5,
                    ha="right", fontweight="bold")
        fig.text(0.53, 0.05, "Hotend heats at 2.5C/s (simulated). Run it yourself: "
                 "gcodeguard bench agent", color=INK2, fontsize=10.5)
        fig.savefig(frames_dir / f"f{frame:04d}.png", facecolor=SURFACE)
        plt.close(fig)
    # hold the last frame
    last = frames_dir / f"f{total - 1:04d}.png"
    for extra in range(total, total + 60):
        shutil.copy(last, frames_dir / f"f{extra:04d}.png")

    mp4, gif = OUT / "agent-demo.mp4", OUT / "agent-demo.gif"
    pattern = str(frames_dir / "f%04d.png")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "15", "-i", pattern,
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", "-movflags", "+faststart",
                    str(mp4)], check=True)
    palette = frames_dir / "palette.png"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", pattern, "-vf",
                    "fps=12,scale=960:-1:flags=lanczos,palettegen=max_colors=64", str(palette)],
                   check=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "15", "-i", pattern, "-i",
                    str(palette), "-lavfi",
                    "fps=12,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4",
                    str(gif)], check=True)
    shutil.rmtree(frames_dir)
    if harms_off:
        print("unguarded harms:", ", ".join(e.kind for e in harms_off))
    return mp4, gif


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    targets = sys.argv[1:] or ["scan", "agent"]
    if "scan" in targets:
        print("wrote", make_scan_gif())
    if "agent" in targets:
        print("wrote", *make_agent_video())


if __name__ == "__main__":
    main()
