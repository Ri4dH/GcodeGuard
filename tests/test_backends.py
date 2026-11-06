from unittest.mock import MagicMock

import pytest

from gcodeguard.backends import BackendError, make_backend, validate_filename
from gcodeguard.backends.base import HttpClient
from gcodeguard.backends.moonraker import MoonrakerBackend
from gcodeguard.backends.octoprint import OctoPrintBackend


@pytest.mark.parametrize("name", ["../secret.gcode", "a/b.gcode", ".hidden", "x" * 200, "a;rm.gcode", ""])
def test_bad_filenames_rejected(name):
    with pytest.raises(BackendError):
        validate_filename(name)


def test_good_filename():
    assert validate_filename(" Benchy (PLA) v2.gcode ") == "Benchy (PLA) v2.gcode"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x", "octopi.local", "http://"])
def test_bad_urls_rejected(url):
    with pytest.raises(BackendError):
        HttpClient(url, None)


def test_make_backend_requires_url():
    with pytest.raises(BackendError):
        make_backend("octoprint")
    assert make_backend("sim").name == "sim"


def test_octoprint_calls():
    http = MagicMock()
    backend = OctoPrintBackend("http://x", None, client=http)
    backend.send_gcode(["G28", "M104 S200"])
    http.call.assert_called_with("POST", "/api/printer/command", body={"commands": ["G28", "M104 S200"]})
    backend.start_print("cube.gcode")
    http.call.assert_called_with("POST", "/api/files/local/cube.gcode",
                                 body={"command": "select", "print": True})
    backend.upload("cube.gcode", "G28\n")
    http.upload.assert_called_once()
    backend.emergency_stop()
    http.call.assert_called_with("POST", "/api/printer/command", body={"commands": ["M112"]})


def test_octoprint_status_and_files():
    http = MagicMock()
    http.call.side_effect = [
        {"state": {"text": "Printing"}, "temperature": {"tool0": {"actual": 200, "target": 210},
                                                         "bed": {"actual": 60, "target": 60}}},
        {"files": [{"type": "machinecode", "path": "a.gcode", "size": 1},
                   {"type": "folder", "children": [{"type": "machinecode", "path": "d/b.gcode"}]}]},
    ]
    backend = OctoPrintBackend("http://x", None, client=http)
    assert backend.status() == {"state": "Printing", "hotend": {"actual": 200, "target": 210},
                                "bed": {"actual": 60, "target": 60}}
    assert [f["name"] for f in backend.list_files()] == ["a.gcode", "d/b.gcode"]


def test_octoprint_read_file_validates_each_part():
    backend = OctoPrintBackend("http://x", None, client=MagicMock())
    with pytest.raises(BackendError):
        backend.read_file("d/../../etc/passwd")


def test_moonraker_calls():
    http = MagicMock()
    http.call.return_value = {"result": {"status": {
        "extruder": {"temperature": 25, "target": 0}, "heater_bed": {"temperature": 25, "target": 0},
        "print_stats": {"state": "standby"}, "display_status": {"message": "hi"}}}}
    backend = MoonrakerBackend("http://x", "k", client=http)
    status = backend.status()
    assert status["state"] == "standby" and status["display_message"] == "hi"
    backend.send_gcode(["G28", "G1 X1"])
    http.call.assert_called_with("POST", "/printer/gcode/script", body={"script": "G28\nG1 X1"})
    backend.start_print("a.gcode")
    http.call.assert_called_with("POST", "/printer/print/start", query={"filename": "a.gcode"})


def test_http_client_sends_api_key(monkeypatch):
    captured = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.header_items())
        captured["url"] = req.full_url
        return Resp()

    monkeypatch.setattr("gcodeguard.backends.base.request.urlopen", fake_urlopen)
    client = HttpClient("http://printer:7125/", "secret")
    assert client.call("GET", "/x", query={"a": "1"}) == {"ok": True}
    assert captured["url"] == "http://printer:7125/x?a=1"
    assert captured["headers"]["X-api-key"] == "secret"
