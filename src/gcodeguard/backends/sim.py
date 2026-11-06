"""Backend that drives the in-process virtual printer (demos, tests, benchmark)."""

from __future__ import annotations

from typing import Any

from gcodeguard.backends.base import BackendError, validate_filename
from gcodeguard.simulator import VirtualPrinter


class SimBackend:
    name = "sim"

    def __init__(self, printer: VirtualPrinter | None = None,
                 files: dict[str, str] | None = None, display_message: str = "") -> None:
        self.printer = printer or VirtualPrinter()
        self.files: dict[str, str] = dict(files or {})
        self.display_message = display_message
        self.printed: list[str] = []

    def status(self) -> dict[str, Any]:
        out = self.printer.status()
        out["state"] = "halted" if self.printer.killed else "ready"
        if self.display_message:
            out["display_message"] = self.display_message
        return out

    def send_gcode(self, lines: list[str]) -> list[str]:
        return [self.printer.send(line) for line in lines]

    def list_files(self) -> list[dict[str, Any]]:
        return [{"name": n, "size": len(c)} for n, c in sorted(self.files.items())]

    def read_file(self, name: str) -> str:
        name = validate_filename(name)
        if name not in self.files:
            raise BackendError(f"no such file: {name}")
        return self.files[name]

    def upload(self, name: str, content: str) -> None:
        self.files[validate_filename(name)] = content

    def start_print(self, name: str) -> None:
        content = self.read_file(name)
        self.printed.append(name)
        self.printer.run(content.splitlines())

    def cancel(self) -> None:
        self.printer.send("M104 S0")
        self.printer.send("M140 S0")

    def emergency_stop(self) -> None:
        self.printer.send("M112")
