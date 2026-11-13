"""State shared between monitors so that separate observations can be tied together.

The file monitor records what was dropped; the process and autorun monitors ask
whether a program or a persistence entry points at one of those files; the process
monitor records which processes it flagged so the network monitor can watch them.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from filespy.paths import norm


@dataclass
class DropRecord:
    path: str
    sha256: str
    ts: float
    event_id: str
    score: int = 0


@dataclass
class FlaggedProcess:
    pid: int
    create_time: float
    name: str
    exe: str
    score: int
    reason: str


class SharedState:
    def __init__(self, max_drops: int = 20000, drop_ttl: float = 86400.0) -> None:
        self._lock = threading.Lock()
        self._drops: OrderedDict[str, DropRecord] = OrderedDict()
        self._flagged: dict[int, FlaggedProcess] = {}
        self._max_drops = max_drops
        self._drop_ttl = drop_ttl
        self.own_pid = os.getpid()
        self.started = time.time()

    # -- dropped files --------------------------------------------------------
    def note_drop(self, path: str, sha256: str = "", event_id: str = "", score: int = 0) -> None:
        key = norm(path)
        with self._lock:
            self._drops.pop(key, None)
            self._drops[key] = DropRecord(path, sha256, time.time(), event_id, score)
            while len(self._drops) > self._max_drops:
                self._drops.popitem(last=False)

    def forget_drop(self, path: str) -> None:
        with self._lock:
            self._drops.pop(norm(path), None)

    def lookup_drop(self, path: str) -> DropRecord | None:
        if not path:
            return None
        key = norm(path)
        with self._lock:
            record = self._drops.get(key)
            if record and time.time() - record.ts > self._drop_ttl:
                del self._drops[key]
                return None
            return record

    def drop_count(self) -> int:
        with self._lock:
            return len(self._drops)

    # -- flagged processes ----------------------------------------------------
    def flag_process(self, pid: int, create_time: float, name: str, exe: str, score: int, reason: str) -> None:
        with self._lock:
            self._flagged[pid] = FlaggedProcess(pid, create_time, name, exe, score, reason)
            if len(self._flagged) > 5000:
                for old in sorted(self._flagged, key=lambda p: self._flagged[p].create_time)[:1000]:
                    del self._flagged[old]

    def flagged(self, pid: int) -> FlaggedProcess | None:
        with self._lock:
            return self._flagged.get(pid)

    def unflag(self, pid: int) -> None:
        with self._lock:
            self._flagged.pop(pid, None)
