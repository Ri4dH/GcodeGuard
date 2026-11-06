"""OctoPrint REST backend (https://docs.octoprint.org/en/master/api/)."""

from __future__ import annotations

from typing import Any
from urllib import parse

from gcodeguard.backends.base import BackendError, HttpClient, validate_filename


class OctoPrintBackend:
    name = "octoprint"

    def __init__(self, url: str, api_key: str | None, client: HttpClient | None = None) -> None:
        self.http = client or HttpClient(url, api_key)

    def status(self) -> dict[str, Any]:
        data = self.http.call("GET", "/api/printer") or {}
        temps = data.get("temperature", {})
        return {
            "state": data.get("state", {}).get("text", "unknown"),
            "hotend": {k: temps.get("tool0", {}).get(k) for k in ("actual", "target")},
            "bed": {k: temps.get("bed", {}).get(k) for k in ("actual", "target")},
        }

    def send_gcode(self, lines: list[str]) -> list[str]:
        if lines:
            self.http.call("POST", "/api/printer/command", body={"commands": lines})
        return ["queued"] * len(lines)

    def list_files(self) -> list[dict[str, Any]]:
        data = self.http.call("GET", "/api/files/local", query={"recursive": "true"}) or {}
        out: list[dict[str, Any]] = []
        stack = list(data.get("files", []))
        while stack:
            entry = stack.pop()
            if entry.get("type") == "folder":
                stack.extend(entry.get("children", []))
            else:
                out.append({"name": entry.get("path") or entry.get("name"), "size": entry.get("size")})
        return sorted(out, key=lambda e: str(e["name"]))

    def read_file(self, name: str) -> str:
        path = "/".join(validate_filename(part) for part in name.split("/"))
        text = self.http.call("GET", "/downloads/files/local/" + parse.quote(path))
        if not isinstance(text, str):
            raise BackendError(f"could not download {name}")
        return text

    def upload(self, name: str, content: str) -> None:
        self.http.upload("/api/files/local", validate_filename(name), content, {"select": "false"})

    def start_print(self, name: str) -> None:
        name = validate_filename(name)
        self.http.call("POST", "/api/files/local/" + parse.quote(name),
                       body={"command": "select", "print": True})

    def cancel(self) -> None:
        self.http.call("POST", "/api/job", body={"command": "cancel"})

    def emergency_stop(self) -> None:
        self.http.call("POST", "/api/printer/command", body={"commands": ["M112"]})
