# Security policy

GcodeGuard is a safety tool, so a bypass is a security bug. Examples:

* G-code the printer runs but GcodeGuard parses differently (parser differentials)
* A command that should be blocked under a built-in profile but isn't
* A way to make the OctoPrint plugin, Klipper module, or MCP server forward an unchecked command
* Path traversal or injection through file names, URLs, or policy files

## Reporting

Please **don't open a public issue**. Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository) and include:

* the G-code or tool call that gets through,
* the profile and options you used (`gcodeguard --version`, `--profile ...`),
* what the printer would do.

Expect a reply within a week. Fixes ship with a regression test and a note in the release.

## Scope

Attacks that bypass the host entirely (SD-card printing, direct serial access, malicious
firmware) are out of scope by design. See [docs/threat-model.md](docs/threat-model.md).
Never test attacks on a printer you can't watch, and never on someone else's machine without
permission. The simulator (`gcodeguard simulate`, `--backend sim`) exists so you don't have to.
