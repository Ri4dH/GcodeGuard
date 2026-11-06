# Threat model

## What we protect

| Asset | Harm we try to prevent |
|---|---|
| People and the room | Fire from heaters left on, toxic fumes from overheated PTFE liners, burns |
| The machine | Carriages driven into the frame, overheated stepper drivers, jams from cold extrusion |
| The parts | Silently weakened functional parts (under-extrusion, skipped layers, poor layer bonding) |
| The configuration | Calibration or limits changed *and saved*, so the damage survives a reboot |
| The host computer | Shell commands run through printer macros |

## Who attacks, and how

1. **A poisoned G-code file.** Downloaded from a model site, shared in a class, or tampered with on
   a network share. This is the classic attack in additive-manufacturing security research
   (e.g. sabotage that weakens a part without changing how it looks).
2. **An AI agent that was prompt-injected.** An LLM agent drives the printer through tools (MCP,
   OctoPrint/Moonraker APIs). Instructions planted in content the agent reads (a model description,
   a web page, a file name, a comment inside a G-code file, a status message on the printer)
   make it send harmful commands. The agent is honest but fooled.
3. **An unsafe request.** A person (or an agent acting for them) asks for something the hardware
   can't safely do, like 300 °C on a PTFE-lined hotend. No attacker needed.

## Where GcodeGuard sits

```
 slicer / human / AI agent ──► [ GcodeGuard ] ──► OctoPrint / Klipper / Moonraker ──► firmware ──► printer
                                    │
                         pre-print scan of files
                         line-by-line live filter
                         idle-heater watchdog
                         hash-chained audit log
```

GcodeGuard runs on the **host**: as a CLI before printing, as an OctoPrint plugin, as a Klipper
extras module, or as the MCP server an agent talks to. It decides with deterministic rules over a
parsed, stateful model of the machine (position, heaters, extrusion history). It never asks an LLM
whether a command is safe.

**Design rules**

* **Machine limits come from policy, not from the request.** Firmware limits are often far above
  what the hardware tolerates (stock Ender-3 Marlin allows 260 °C targets; its PTFE liner degrades
  around 240–250 °C).
* **The parser is at least as lenient as firmware.** `n12 m104s300*45` and `M104 S 300` are parsed
  exactly like `M104 S300`, so nothing hides in the gap between what the firewall reads and what
  the printer runs.
* **Safety commands are never blocked.** `M112`, `M108`, `M410`, `CANCEL_PRINT`,
  `TURN_OFF_HEATERS` and pause/abort always pass, whatever the policy says.
* **Fail closed.** If the OctoPrint hook errors, the command is dropped. Klipper aborts on errors
  inside the wrapper, and MCP tool errors send nothing.
* **Files are judged as a whole before printing** (the pre-print gate). Once OctoPrint or Klipper
  is streaming a file, an agent can no longer step in, so a file with blocked commands or
  sabotage warnings is refused up front.
* **Tell the agent why.** Blocked tool calls return the reason and a note that the instruction may
  be a prompt injection, so the model can explain it to the user instead of looking for a workaround.

## Out of scope / known limits

* **Anything that bypasses the host**: printing from the SD card or USB stick, another program
  talking to the serial port directly, or compromised firmware. A hardware monitor such as
  [Firewall3D](https://arxiv.org/abs/2607.10484) is complementary here. GcodeGuard does flag `M23`
  and `M28`, which start SD prints or write SD files.
* **Opaque macros.** In the CLI and the OctoPrint plugin, a Klipper macro like `PRINT_START` is a
  black box. The Klipper module covers this, because it wraps the commands that macros themselves
  run.
* **Sabotage detection is heuristic.** It compares each layer with the print's own baseline. An
  attacker who knows the thresholds can stay under them, for example a 24 °C temperature drop
  when the limit is 25 °C, or short under-extruded runs. Under-extruding the *whole* print from
  layer 0 has no baseline to compare against. The physics check is informational only, because
  real slicer output is scaled by extruder calibration that a file doesn't reveal.
* **Geometry is not verified.** GcodeGuard doesn't check that a toolpath matches the intended
  model. That needs the design file (see C3PO and the ML literature in the README).
* **Not a replacement** for firmware thermal-runaway protection, a smoke detector, or watching
  your printer.
