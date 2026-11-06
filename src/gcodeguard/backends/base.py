"""Backend interface and shared HTTP helpers (stdlib only)."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Protocol
from urllib import parse, request
from urllib.error import HTTPError, URLError

_FILENAME = re.compile(r"^[\w\-. ()]{1,128}$")


class BackendError(RuntimeError):
    pass


def validate_filename(name: str) -> str:
    """Reject path traversal and odd characters before a name reaches a printer host."""
    name = name.strip()
    if not _FILENAME.match(name) or ".." in name or name.startswith("."):
        raise BackendError(f"invalid file name {name!r}: use letters, digits, '-', '_', '.', ' ' only")
    return name


class PrinterBackend(Protocol):
    name: str

    def status(self) -> dict[str, Any]: ...
    def send_gcode(self, lines: list[str]) -> list[str]: ...
    def list_files(self) -> list[dict[str, Any]]: ...
    def read_file(self, name: str) -> str: ...
    def upload(self, name: str, content: str) -> None: ...
    def start_print(self, name: str) -> None: ...
    def cancel(self) -> None: ...
    def emergency_stop(self) -> None: ...


class HttpClient:
    def __init__(self, base_url: str, api_key: str | None, timeout: float = 10.0) -> None:
        parsed = parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise BackendError(f"invalid printer URL {base_url!r} (expected http(s)://host[:port])")
        self.base = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"User-Agent": "gcodeguard", "Accept": "application/json"}
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
        headers.update(extra or {})
        return headers

    def call(self, method: str, path: str, body: Any = None, query: dict[str, str] | None = None,
             raw: bytes | None = None, content_type: str | None = None) -> Any:
        url = self.base + path
        if query:
            url += "?" + parse.urlencode(query)
        data = raw
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif content_type:
            headers["Content-Type"] = content_type
        req = request.Request(url, data=data, method=method, headers=headers)
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (scheme checked)
                payload = resp.read()
        except HTTPError as exc:
            detail = exc.read()[:300].decode(errors="replace")
            raise BackendError(f"{method} {path}: HTTP {exc.code} {detail}") from exc
        except URLError as exc:
            raise BackendError(f"{method} {path}: {exc.reason}") from exc
        if not payload:
            return None
        try:
            return json.loads(payload)
        except ValueError:
            return payload.decode(errors="replace")

    def upload(self, path: str, filename: str, content: str, fields: dict[str, str]) -> Any:
        boundary = uuid.uuid4().hex
        parts: list[bytes] = []
        for key, value in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
                         f"{value}\r\n".encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                     f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode())
        parts.append(content.encode() + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self.call("POST", path, raw=b"".join(parts),
                         content_type=f"multipart/form-data; boundary={boundary}")
