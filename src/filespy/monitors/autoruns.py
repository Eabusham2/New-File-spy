"""Autorun monitor: reports persistence entries that appear, change or disappear."""

from __future__ import annotations

import logging

from filespy import sanitize
from filespy.autoruns import AutorunEntry, get_providers, label, score_entry
from filespy.monitors.base import Monitor
from filespy.textutil import added_lines

log = logging.getLogger("filespy")
SLOW_EVERY = 3


class AutorunMonitor(Monitor):
    name = "autorun"

    def setup(self) -> None:
        self.interval = self.ctx.config.autoruns.interval
        self.providers = get_providers(self.ctx)
        if not self.providers:
            raise RuntimeError("no autostart locations can be read on this system")
        self._snapshots: dict[str, dict[tuple[str, str, str], AutorunEntry]] = {}
        self._broken: set[str] = set()
        self._tick = 0
        total = 0
        for provider in self.providers:
            snapshot = self._collect(provider)
            if snapshot is not None:
                self._snapshots[provider.name] = snapshot
                total += len(snapshot)
        self.system("info", f"Tracking {total} autostart entries")

    def _collect(self, provider) -> dict[tuple[str, str, str], AutorunEntry] | None:  # noqa: ANN001
        try:
            snapshot = {entry.key: entry for entry in provider.collect()}
        except Exception as exc:  # noqa: BLE001 - keep the other providers running
            if provider.name not in self._broken:
                self._broken.add(provider.name)
                log.exception("autorun provider %s failed", provider.name)
                self.system("warning", f"Autostart source '{provider.name}' could not be read: {type(exc).__name__}: {exc}")
            return None
        self._broken.discard(provider.name)
        return snapshot

    def poll(self) -> None:
        self._tick += 1
        for provider in self.providers:
            if provider.slow and self._tick % SLOW_EVERY:
                continue
            current = self._collect(provider)
            if current is None:
                continue
            previous = self._snapshots.get(provider.name)
            self._snapshots[provider.name] = current
            if previous is None:
                continue  # first successful read is the baseline
            for key, entry in current.items():
                old = previous.get(key)
                if old is None:
                    self._report(entry, "added")
                elif old.command != entry.command:
                    self._report(entry, "changed", old)
            for key, entry in previous.items():
                if key not in current:
                    self._report(entry, "removed")

    def entries(self) -> list[AutorunEntry]:
        return [entry for snapshot in self._snapshots.values() for entry in snapshot.values()]

    def _report(self, entry: AutorunEntry, action: str, old: AutorunEntry | None = None) -> None:
        what = label(entry.category)
        name = sanitize.clean(entry.name, 100)
        details = entry.to_dict()
        details["path"] = entry.target
        if action == "removed":
            self.emit("autorun", "removed", f"A {what} was removed: {name}", entry.location, details=details)
            return
        added_text = ""
        if entry.content and old is not None:
            lines = added_lines(old.content, entry.content)
            details["added_lines"] = [sanitize.clean(line, 300) for line in lines]
            added_text = "\n".join(lines)
            if not lines:
                # Only deletions or comment edits: worth recording, not worth an alert.
                self.emit("autorun", "changed", f"A {what} was edited (nothing added): {name}", entry.location, details=details)
                return
        if old is not None:
            details["previous_command"] = old.command
        indicators = score_entry(entry, self.ctx, action, added_text)
        verb = "added" if action == "added" else "changed"
        self.emit("autorun", action, f"A {what} was {verb}: {name}", entry.location, indicators, details)
