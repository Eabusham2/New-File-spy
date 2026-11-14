"""SQLite event store. One connection guarded by a lock; safe to call from any thread."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from filespy.events import Event, Severity
from filespy.sanitize import json_safe

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    session TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    severity INTEGER NOT NULL,
    score INTEGER NOT NULL,
    title TEXT NOT NULL,
    subject TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_session ON events (session, ts);
CREATE INDEX IF NOT EXISTS events_severity ON events (severity, ts);
"""


class EventStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._db.executescript(_SCHEMA)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        self._db.commit()
        if new and os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def add(self, event: Event) -> None:
        payload = json.dumps(json_safe({"indicators": [i.to_dict() for i in event.indicators], "details": event.details}))
        row = (event.id, event.ts, event.session, event.category, event.action, int(event.severity),
               event.score, event.title, event.subject, payload)
        with self._lock:
            # An upsert keeps the row's position, so events with equal timestamps stay in arrival order.
            self._db.execute(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "ts=excluded.ts, session=excluded.session, category=excluded.category, action=excluded.action, "
                "severity=excluded.severity, score=excluded.score, title=excluded.title, subject=excluded.subject, "
                "data=excluded.data",
                row,
            )
            self._db.commit()

    def query(
        self,
        since: float | None = None,
        until: float | None = None,
        min_severity: Severity | int = Severity.INFO,
        categories: list[str] | None = None,
        session: str | None = None,
        text: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> list[Event]:
        clauses, params = ["severity >= ?"], [int(min_severity)]
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        if categories:
            clauses.append(f"category IN ({','.join('?' * len(categories))})")
            params.extend(categories)
        if session:
            clauses.append("session = ?")
            params.append(session)
        if text:
            clauses.append("(title LIKE ? OR subject LIKE ?)")
            params.extend([f"%{text}%", f"%{text}%"])
        sql = "SELECT id, ts, session, category, action, severity, score, title, subject, data FROM events WHERE "
        direction = "DESC" if newest_first else "ASC"
        sql += " AND ".join(clauses) + f" ORDER BY ts {direction}, rowid {direction}"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [_row_to_event(row) for row in rows]

    def sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        sql = ("SELECT session, MIN(ts), MAX(ts), COUNT(*), MAX(severity) FROM events "
               "GROUP BY session ORDER BY MIN(ts) DESC LIMIT ?")
        with self._lock:
            rows = self._db.execute(sql, (limit,)).fetchall()
        return [{"session": r[0], "start": r[1], "end": r[2], "events": r[3], "max_severity": Severity(r[4]).label} for r in rows]

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def prune(self, retention_days: int, max_events: int) -> int:
        """Delete events older than the retention period and keep at most ``max_events``."""
        removed = 0
        with self._lock:
            if retention_days > 0:
                cutoff = time.time() - retention_days * 86400
                removed += self._db.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            total = int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            if total > max_events:
                removed += self._db.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts ASC LIMIT ?)",
                    (total - max_events,),
                ).rowcount
            self._db.commit()
        return removed

    def close(self) -> None:
        with self._lock:
            try:
                self._db.commit()
                self._db.close()
            except sqlite3.Error:
                pass


def _row_to_event(row: tuple) -> Event:
    try:
        payload = json.loads(row[9])
    except ValueError:
        payload = {}
    data = {
        "id": row[0], "ts": row[1], "session": row[2], "category": row[3], "action": row[4],
        "severity": int(row[5]), "score": row[6], "title": row[7], "subject": row[8],
        "indicators": payload.get("indicators", []), "details": payload.get("details", {}),
    }
    return Event.from_dict(data)
