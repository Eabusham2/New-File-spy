"""Wires the monitors, the event store, the alert channels and the optional responder together."""

from __future__ import annotations

import os
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import TextIO

from filespy.alerts import AlertManager
from filespy.config import Config
from filespy.context import Context
from filespy.events import Event, EventBus, Severity, make_event
from filespy.export import auto_export
from filespy.monitors.autoruns import AutorunMonitor
from filespy.monitors.base import Monitor
from filespy.monitors.files import FileMonitor
from filespy.monitors.network import NetworkMonitor
from filespy.monitors.processes import ProcessMonitor
from filespy.monitors.settings import SettingsMonitor
from filespy.paths import ensure_private_dir
from filespy.registry import make_registry
from filespy.response import Responder
from filespy.storage import EventStore

MONITORS: dict[str, type[Monitor]] = {
    "files": FileMonitor,
    "processes": ProcessMonitor,
    "network": NetworkMonitor,
    "autoruns": AutorunMonitor,
    "settings": SettingsMonitor,
}


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


class App:
    def __init__(
        self,
        cfg: Config,
        data_dir: Path | str,
        only: set[str] | None = None,
        stream: TextIO | None = None,
        console: bool = True,
        as_json: bool = False,
    ) -> None:
        self.cfg = cfg
        self.data_dir = ensure_private_dir(data_dir)
        self.session = uuid.uuid4().hex[:12]
        self.bus = EventBus(self.session)
        self.store = EventStore(self.data_dir / "events.db")
        self.ctx = Context(cfg, self.bus, self.data_dir, registry=make_registry())
        self.alerts = AlertManager(cfg, self.data_dir, stream, console, as_json)
        self.responder = Responder(self.ctx)
        self._closed = False
        self.counts: Counter[str] = Counter()
        self.bus.subscribe(self._record)
        self.bus.subscribe(self.alerts.handle)
        if self.responder.enabled:
            self.bus.subscribe(self.responder.handle)
        names = [n for n in MONITORS if getattr(cfg, n).enabled and (only is None or n in only)]
        self.monitors: list[Monitor] = [MONITORS[name](self.ctx) for name in names]
        self.monitor_names = names

    def _record(self, event: Event) -> None:
        if self._closed:
            return
        if event.category != "system":
            self.counts[event.severity.label] += 1
        self.store.add(event)

    def start(self, ready_timeout: float = 90.0) -> None:
        self.store.prune(self.cfg.storage.retention_days, self.cfg.storage.max_events)
        for warning in list(self.cfg.warnings) + list(self.alerts.warnings):
            self.bus.publish(make_event("system", "warning", f"Configuration: {warning}", min_severity=Severity.LOW))
        for monitor in self.monitors:
            monitor.start()
        deadline = time.monotonic() + ready_timeout
        for monitor in self.monitors:
            monitor.ready.wait(max(0.1, deadline - time.monotonic()))
        running = [name for name, monitor in zip(self.monitor_names, self.monitors) if not monitor.failed]
        self.bus.publish(make_event("system", "info", f"FileSpy is watching: {', '.join(running) or 'nothing'}", "app",
                                    details={"session": self.session, "monitors": running}))

    def stop(self) -> list[Path]:
        """Stop everything; returns the export files written if auto-export is on."""
        for monitor in self.monitors:
            monitor.stop()
        for monitor in self.monitors:
            monitor.join(10)
        exported: list[Path] = []
        if self.cfg.export.auto_on_exit:
            try:
                exported = auto_export(self.store.query(session=self.session), self.cfg, self.data_dir, self.session)
            except OSError as exc:
                self.bus.publish(make_event("system", "error", f"Export failed: {exc}", min_severity=Severity.MEDIUM))
        self.alerts.close()
        self._closed = True
        self.store.close()
        return exported

    def run(self, duration: float | None = None) -> list[Path]:
        self.start()
        try:
            end = None if duration is None else time.monotonic() + duration
            while end is None or time.monotonic() < end:
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        return self.stop()

    def summary(self) -> str:
        total = sum(self.counts.values())
        if not total:
            return "No events this session."
        parts = [f"{self.counts[s.label]} {s.label}" for s in reversed(Severity) if self.counts[s.label]]
        return f"{total} events this session: " + ", ".join(parts) + "."
