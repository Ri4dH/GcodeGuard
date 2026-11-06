"""Append-only, hash-chained audit log (JSON Lines).

Every record carries the SHA-256 of the previous record, so deleting or editing
any line breaks the chain and ``verify`` reports where. This is tamper-*evident*,
not tamper-*proof*: someone with write access can rewrite the whole file, so
ship the log off-box if that matters to you.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, clock=time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        record = json.loads(last)
        return int(record["seq"]), str(record["hash"])

    def record(self, event: str, payload: dict) -> None:
        with self._lock:
            body = {"seq": self._seq + 1, "ts": round(self._clock(), 3), "event": event,
                    "prev": self._prev, "data": payload}
            digest = _digest(self._prev, body)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({**body, "hash": digest}, sort_keys=True) + "\n")
            self._seq, self._prev = body["seq"], digest


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None


def verify(path: str | Path) -> VerifyResult:
    prev, count = GENESIS, 0
    with Path(path).open(encoding="utf-8") as fh:
        for number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                claimed = record.pop("hash")
            except (ValueError, KeyError):
                return VerifyResult(False, count, f"line {number}: not a valid audit record")
            if record.get("prev") != prev:
                return VerifyResult(False, count, f"line {number}: chain broken (record missing or reordered)")
            if _digest(prev, record) != claimed:
                return VerifyResult(False, count, f"line {number}: contents were modified")
            if record.get("seq") != count + 1:
                return VerifyResult(False, count, f"line {number}: unexpected sequence number")
            prev, count = claimed, count + 1
    return VerifyResult(True, count)
