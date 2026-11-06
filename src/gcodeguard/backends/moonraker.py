"""Moonraker (Klipper) REST backend (https://moonraker.readthedocs.io/en/latest/web_api/)."""

from __future__ import annotations

from typing import Any
from urllib import parse

from gcodeguard.backends.base import BackendError, HttpClient, validate_filename


class MoonrakerBackend:
    name = "moonraker"

    def __init__(self, url: str, api_key: str | None, client: HttpClient | None = None) -> None:
        self.http = client or HttpClient(url, api_key)

    def status(self) -> dict[str, Any]:
        query = {"extruder": "temperature,target", "heater_bed": "temperature,target",
                 "print_stats": "state,filename", "display_status": "message"}
        data = self.http.call("GET", "/printer/objects/query", query=query) or {}
        status = data.get("result", {}).get("status", {})
        ext, bed = status.get("extruder", {}), status.get("heater_bed", {})
        out = {
            "state": status.get("print_stats", {}).get("state", "unknown"),
            "file": status.get("print_stats", {}).get("filename"),
            "hotend": {"actual": ext.get("temperature"), "target": ext.get("target")},
            "bed": {"actual": bed.get("temperature"), "target": bed.get("target")},
        }
        message = status.get("display_status", {}).get("message")
        if message:
            out["display_message"] = message
        return out

    def send_gcode(self, lines: list[str]) -> list[str]:
        if lines:
            self.http.call("POST", "/printer/gcode/script", body={"script": "\n".join(lines)})
        return ["ok"] * len(lines)

    def list_files(self) -> list[dict[str, Any]]:
        data = self.http.call("GET", "/server/files/list", query={"root": "gcodes"}) or {}
        return [{"name": f.get("path"), "size": f.get("size")} for f in data.get("result", [])]

    def read_file(self, name: str) -> str:
        path = "/".join(validate_filename(part) for part in name.split("/"))
        text = self.http.call("GET", "/server/files/gcodes/" + parse.quote(path))
        if not isinstance(text, str):
            raise BackendError(f"could not download {name}")
        return text

    def upload(self, name: str, content: str) -> None:
        self.http.upload("/server/files/upload", validate_filename(name), content, {"root": "gcodes"})

    def start_print(self, name: str) -> None:
        self.http.call("POST", "/printer/print/start", query={"filename": validate_filename(name)})

    def cancel(self) -> None:
        self.http.call("POST", "/printer/print/cancel")

    def emergency_stop(self) -> None:
        self.http.call("POST", "/printer/emergency_stop")
