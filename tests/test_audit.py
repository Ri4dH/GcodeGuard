import json

from gcodeguard.audit import AuditLog, verify


def make_log(tmp_path, n=3):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, clock=lambda: 1000.0)
    for i in range(n):
        log.record("decision", {"i": i})
    return path


def test_chain_verifies(tmp_path):
    path = make_log(tmp_path)
    result = verify(path)
    assert result.ok and result.records == 3


def test_resume_appends_to_existing_chain(tmp_path):
    path = make_log(tmp_path, 2)
    AuditLog(path).record("decision", {"i": 99})
    assert verify(path).records == 3


def test_edit_is_detected(tmp_path):
    path = make_log(tmp_path)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["data"]["i"] = 42
    lines[1] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    result = verify(path)
    assert not result.ok and "modified" in result.error


def test_deletion_is_detected(tmp_path):
    path = make_log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = verify(path)
    assert not result.ok and "chain broken" in result.error


def test_garbage_is_detected(tmp_path):
    path = make_log(tmp_path)
    path.write_text(path.read_text() + "not json\n")
    assert not verify(path).ok
