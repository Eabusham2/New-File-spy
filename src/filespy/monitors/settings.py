"""Settings monitor: reports tampering with security-relevant configuration."""

from __future__ import annotations

import logging
from typing import Any

from filespy.events import Indicator
from filespy.monitors.base import Monitor
from filespy.settingsmon import Change, get_providers

log = logging.getLogger("filespy")


class SettingsMonitor(Monitor):
    name = "settings"

    def setup(self) -> None:
        self.interval = self.ctx.config.settings.interval
        self.providers = get_providers(self.ctx)
        if not self.providers:
            raise RuntimeError("no settings can be read on this system")
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._broken: set[str] = set()
        self._tick = 0
        count = 0
        for provider in self.providers:
            snapshot = self._snapshot(provider)
            if snapshot is not None:
                self._snapshots[provider.name] = snapshot
                count += len(snapshot)
        self.system("info", f"Tracking {count} security settings")

    def _snapshot(self, provider) -> dict[str, Any] | None:  # noqa: ANN001
        try:
            return provider.snapshot()
        except Exception as exc:  # noqa: BLE001 - keep the other providers running
            if provider.name not in self._broken:
                self._broken.add(provider.name)
                log.exception("settings provider %s failed", provider.name)
                self.system("warning", f"Settings source '{provider.name}' could not be read: {type(exc).__name__}: {exc}")
            return None

    def poll(self) -> None:
        self._tick += 1
        for provider in self.providers:
            if self._tick % max(1, provider.every):
                continue
            current = self._snapshot(provider)
            if current is None:
                continue
            previous = self._snapshots.get(provider.name)
            self._snapshots[provider.name] = current
            if previous is None:
                continue
            for change in provider.changes(previous, current):
                self.report(change)

    def report(self, change: Change) -> None:
        details = dict(change.details)
        details["category"] = change.category
        details["dangerous"] = change.danger
        indicator = Indicator(f"setting.{change.id}", change.score, change.title, change.mitre)
        self.emit("setting", "changed", change.title, change.subject, [indicator], details)
