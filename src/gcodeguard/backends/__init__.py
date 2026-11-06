"""Printer backends: where guarded commands actually go."""

from __future__ import annotations

import os

from gcodeguard.backends.base import BackendError, PrinterBackend, validate_filename
from gcodeguard.backends.sim import SimBackend


def make_backend(kind: str, url: str | None = None, api_key_env: str | None = None) -> PrinterBackend:
    if kind == "sim":
        return SimBackend()
    if not url:
        raise BackendError(f"--url is required for the {kind} backend")
    api_key = os.environ.get(api_key_env or "", "") or None
    if kind == "octoprint":
        from gcodeguard.backends.octoprint import OctoPrintBackend

        return OctoPrintBackend(url, api_key)
    if kind == "moonraker":
        from gcodeguard.backends.moonraker import MoonrakerBackend

        return MoonrakerBackend(url, api_key)
    raise BackendError(f"unknown backend {kind!r}")


__all__ = ["BackendError", "PrinterBackend", "SimBackend", "make_backend", "validate_filename"]
