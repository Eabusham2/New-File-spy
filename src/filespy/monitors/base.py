"""Common thread lifecycle for monitors."""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from typing import Any

from filespy.context import Context
from filespy.events import Event, Indicator, Severity, make_event

log = logging.getLogger("filespy")


class Monitor:
    """Subclasses implement ``setup`` (take the baseline) and ``poll`` (look for changes).

    A failure in ``poll`` is reported once per distinct message and the monitor keeps
    running; a failure in ``setup`` disables only that monitor.
    """

    name = "monitor"
    interval = 1.0

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.ready = threading.Event()
        self.failed = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._reported: set[str] = set()

    # -- to override ----------------------------------------------------------
    def setup(self) -> None:  # pragma: no cover - trivial default
        pass

    def poll(self) -> None:  # pragma: no cover - trivial default
        pass

    def teardown(self) -> None:  # pragma: no cover - trivial default
        pass

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"filespy-{self.name}", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.setup()
        except Exception as exc:  # noqa: BLE001 - one monitor must not take the others down
            log.exception("%s monitor could not start", self.name)
            self.failed = True
            self.system("error", f"The {self.name} monitor could not start: {type(exc).__name__}: {exc}", Severity.MEDIUM)
            self.ready.set()
            return
        self.ready.set()
        while not self._stop.is_set():
            self._wake.wait(self.interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self.poll()
            except Exception as exc:  # noqa: BLE001
                message = f"{type(exc).__name__}: {exc}"
                if message not in self._reported and len(self._reported) < 20:
                    self._reported.add(message)
                    log.exception("%s monitor error", self.name)
                    self.system("warning", f"The {self.name} monitor hit an error and carried on: {message}", Severity.LOW)
        try:
            self.teardown()
        except Exception:  # noqa: BLE001
            log.exception("%s monitor teardown failed", self.name)

    def wake(self) -> None:
        """Ask for an immediate poll."""
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def join(self, timeout: float = 5.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # -- publishing -----------------------------------------------------------
    def emit(
        self,
        category: str,
        action: str,
        title: str,
        subject: str = "",
        indicators: Iterable[Indicator] = (),
        details: dict[str, Any] | None = None,
        min_severity: Severity = Severity.INFO,
    ) -> Event:
        return self.ctx.bus.publish(make_event(category, action, title, subject, indicators, details, min_severity))

    def system(self, action: str, title: str, severity: Severity = Severity.INFO) -> Event:
        return self.emit("system", action, title, self.name, min_severity=severity)
