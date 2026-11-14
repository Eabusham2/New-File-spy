"""Event model, scoring and the in-process event bus."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

log = logging.getLogger("filespy")


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: Any, default: Severity | None = None) -> Severity:
        """Accept a Severity, an int 0-4 or a name in any case."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, bool):
            value = None
        if isinstance(value, int) and 0 <= value <= 4:
            return cls(value)
        if isinstance(value, str):
            name = value.strip().upper()
            if name in cls.__members__:
                return cls[name]
            if name.isdigit() and 0 <= int(name) <= 4:
                return cls(int(name))
        if default is not None:
            return default
        raise ValueError(f"not a severity: {value!r}")


#: (minimum score, severity), highest first.
THRESHOLDS: tuple[tuple[int, Severity], ...] = (
    (100, Severity.CRITICAL),
    (70, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
)
MAX_SCORE = 200


def severity_for(score: int) -> Severity:
    for minimum, severity in THRESHOLDS:
        if score >= minimum:
            return severity
    return Severity.INFO


@dataclass(frozen=True)
class Indicator:
    """One reason an event is suspicious. Scores add up; ``floor`` forces a minimum severity."""

    id: str
    score: int
    description: str
    mitre: str = ""
    floor: Severity | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "score": self.score, "description": self.description}
        if self.mitre:
            data["mitre"] = self.mitre
        if self.floor is not None:
            data["floor"] = self.floor.label
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Indicator:
        floor = data.get("floor")
        return cls(
            id=str(data.get("id", "")),
            score=int(data.get("score", 0)),
            description=str(data.get("description", "")),
            mitre=str(data.get("mitre", "")),
            floor=Severity.parse(floor) if floor is not None else None,
        )


@dataclass
class Event:
    """Something FileSpy observed.

    category: file | process | network | autorun | setting | system
    action:   created, modified, renamed, deleted, started, listen, connect,
              added, removed, changed, burst, info, warning, error, response
    """

    category: str
    action: str
    title: str
    subject: str = ""
    severity: Severity = Severity.INFO
    score: int = 0
    indicators: list[Indicator] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    session: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts)),
            "session": self.session,
            "category": self.category,
            "action": self.action,
            "severity": self.severity.label,
            "score": self.score,
            "title": self.title,
            "subject": self.subject,
            "indicators": [i.to_dict() for i in self.indicators],
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(
            category=str(data.get("category", "")),
            action=str(data.get("action", "")),
            title=str(data.get("title", "")),
            subject=str(data.get("subject", "")),
            severity=Severity.parse(data.get("severity", 0), Severity.INFO),
            score=int(data.get("score", 0)),
            indicators=[Indicator.from_dict(i) for i in data.get("indicators", [])],
            details=dict(data.get("details", {})),
            ts=float(data.get("ts", 0.0)),
            id=str(data.get("id", "")) or uuid.uuid4().hex,
            session=str(data.get("session", "")),
        )


def merge_indicators(indicators: Iterable[Indicator]) -> list[Indicator]:
    """Drop duplicate ids, keeping the highest-scoring copy; order by score descending."""
    best: dict[str, Indicator] = {}
    for ind in indicators:
        cur = best.get(ind.id)
        if cur is None or ind.score > cur.score:
            best[ind.id] = ind
    return sorted(best.values(), key=lambda i: (-i.score, i.id))


def summarize(indicators: Iterable[Indicator]) -> tuple[int, Severity]:
    """Total score (capped) and the resulting severity, honouring floors."""
    items = list(indicators)
    score = max(0, min(MAX_SCORE, sum(i.score for i in items)))
    severity = severity_for(score)
    for ind in items:
        if ind.floor is not None and ind.floor > severity:
            severity = ind.floor
    return score, severity


def make_event(
    category: str,
    action: str,
    title: str,
    subject: str = "",
    indicators: Iterable[Indicator] = (),
    details: dict[str, Any] | None = None,
    min_severity: Severity = Severity.INFO,
) -> Event:
    merged = merge_indicators(indicators)
    score, severity = summarize(merged)
    return Event(
        category=category,
        action=action,
        title=title,
        subject=subject,
        severity=max(severity, min_severity),
        score=score,
        indicators=merged,
        details=dict(details or {}),
    )


Subscriber = Callable[[Event], None]


class EventBus:
    """Synchronous, thread-safe publish/subscribe.

    Callbacks run on the publishing thread, in subscription order. A callback that
    raises is logged and skipped, so one broken subscriber cannot stop a monitor.
    Publishing from inside a callback is allowed.
    """

    def __init__(self, session: str = "") -> None:
        self.session = session
        self._lock = threading.Lock()
        self._subscribers: list[Subscriber] = []
        self.published = 0

    def subscribe(self, callback: Subscriber) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, event: Event) -> Event:
        if not event.session:
            event.session = self.session
        with self._lock:
            subscribers = list(self._subscribers)
            self.published += 1
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # noqa: BLE001 - a subscriber must never break a monitor
                log.exception("event subscriber %r failed", callback)
        return event
