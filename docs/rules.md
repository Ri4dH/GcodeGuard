# Rules

`gcodeguard rules` prints this list from the code. Each finding has a **severity**. The policy
maps severity to an **action** (by default: info → allow, warning → warn, critical → block).
Any rule can be disabled, re-graded, or given its own action in a policy:

```yaml
rules:
  thermal.heater_limit: {action: clamp}        # rewrite M104 S300 to the limit instead of blocking
  firmware.calibration_tamper: {severity: critical}
  sabotage.extrusion_anomaly: false            # disable
```

Rules marked "escalates mid-print" are warnings normally and critical while a print is running.

## Thermal

| Rule | Default | Catches | Notes |
|---|---|---|---|
| `thermal.heater_limit` | critical | Hotend/bed/chamber targets above the profile's limit: `M104/M109/M140/M190/M141/M191`, `M303` autotune, Klipper `SET_HEATER_TEMPERATURE`, `PID_CALIBRATE`. | Clampable. Unnamed Klipper heaters get the chamber limit, the lowest one. |
| `thermal.idle_heater` | critical / warning | A dwell (`G4`) longer than `thermal.max_dwell_s` with heaters on (critical). A file that ends with heaters still on (warning). | `filter`/`sanitize` and the MCP server append heater-off commands. The OctoPrint plugin and MCP server also run a time-based watchdog. Files that end with `PRINT_END`/`END_PRINT` are trusted to switch heaters off. |
| `thermal.cold_extrusion_unlock` | critical | `M302 P1` / `M302 S0`, which disable the firmware's cold-extrusion interlock. | |
| `thermal.low_print_temp` | warning | The active tool set below `min_print_temp` mid-print. | Standby temperatures for idle tools are ignored. |

## Motion

| Rule | Default | Catches | Notes |
|---|---|---|---|
| `motion.out_of_bounds` | critical | Moves outside the build volume (plus `bounds_margin_mm`). Tracks G90/G91, G20/G21, and G92 offsets. | Only for homed axes. Arcs are checked at their end point. |
| `motion.feedrate_limit` | warning | `F` above `max_feedrate_mm_s`. | Clampable. |
| `motion.limits_tamper` | warning / critical | `M203/M201/M204`, `SET_VELOCITY_LIMIT` above machine limits (critical). Motor current changes `M906/M907/SET_TMC_CURRENT` (info). `SET_TMC_FIELD` raw register writes (critical). | PrusaSlicer's MK3 start code sets `M907`, hence info. |
| `motion.endstops_disabled` | critical | `M211 S0`, `M121`, Klipper `FORCE_MOVE`. | |
| `motion.position_override` | critical | `G92 X/Y/Z` mid-print (layer shift), `SET_KINEMATIC_POSITION`, large mid-print `SET_GCODE_OFFSET`. `M206/M428` home offsets (warning). | `G92 E0` is always fine. |
| `motion.steppers_disabled` | critical | `M84/M18/SET_STEPPER_ENABLE ENABLE=0` mid-print while the hotend is hot. | Normal end sequences (heaters off first) are fine. |

## Firmware

| Rule | Default | Catches |
|---|---|---|
| `firmware.persist_settings` | critical | `M500` (save to EEPROM), `M502` (factory reset), `SAVE_CONFIG`, `M997` (firmware update). |
| `firmware.calibration_tamper` | warning, escalates mid-print | `M92` steps/mm, `M301/M304` PID, `M851` probe offset, `M665/M666`, `M425`, `M200`, `SET_HEATER_PID`, `SET_EXTRUDER_ROTATION_DISTANCE`. Bare reporting forms (`M92` with no args) are ignored. |
| `firmware.sd_card` | warning / critical | `M28` writes a file to the SD card (critical; `auto*.g` runs on boot). `M30` deletes a file. `M23/M32/M33` start an SD print that bypasses the host (critical mid-print). |

## Host and policy

| Rule | Default | Catches |
|---|---|---|
| `host.shell` | critical | Klipper `RUN_SHELL_COMMAND`. |
| `host.restart` | warning, escalates mid-print | `RESTART`, `FIRMWARE_RESTART`, `M999`. |
| `policy.blocked_command` | critical | Anything listed in `commands.block`. |
| `policy.unknown_command` | per `commands.unknown` | Commands GcodeGuard doesn't recognise and you haven't listed in `commands.allow` (your macros go there). |

## Sabotage (heuristics)

| Rule | Default | Catches | Notes |
|---|---|---|---|
| `sabotage.flow_override` | warning, escalates mid-print | `M221` flow outside `flow_percent` (default 90–110%), `M220` speed outside `speed_percent`. | |
| `sabotage.temperature_drop` | warning | The hotend dropped more than `max_temp_drop_c` below the print's established temperature. | Temperature towers trip this on purpose. Disable it for calibration prints. |
| `sabotage.layer_gap` | warning | Extrusion resumes more than 1.5 × `max_layer_height_mm` above the previous layer (skipped layers / internal voids). | |
| `sabotage.extrusion_anomaly` | warning | A layer whose median extrusion per mm is outside 0.7–3.5× the print's running baseline, or 25 mm+ of consecutive extrusion outside 0.55–4×. One finding per anomalous region. | Ironing and coasting passes (under 30% of baseline) are excluded, but a layer made *only* of them is flagged. The final layer is exempt (vase-mode and top-surface tapers). A physics check against nozzle and layer height is informational only. |

The pre-print gate (MCP server, `GuardedPrinter`) refuses files with any sabotage warning, not
only files with blocked lines.
