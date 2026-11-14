"""Optional automatic responses. Off unless the user sets a threshold in the configuration."""

from __future__ import annotations

import logging
import os

from filespy import sanitize
from filespy.context import Context
from filespy.events import Event, Severity, make_event
from filespy.paths import basename, classify_location
from filespy.quarantine import Quarantine, QuarantineError

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

log = logging.getLogger("filespy")

#: Never killed, whatever the score: ending these takes the whole system down.
PROTECTED = frozenset({
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "msmpeng.exe",
    "init", "systemd", "launchd", "kernel_task", "loginwindow", "windowserver", "sshd", "dbus-daemon",
})


def is_protected(name: str, exe: str, platform: str) -> bool:
    """A core system process, judged by its name and by where its program lives.

    A program that merely borrows a system name (svchost.exe running from Temp) is not protected.
    """
    if name.lower() not in PROTECTED:
        return False
    if not exe:
        return True  # kernel and protected processes do not reveal their path
    return classify_location(exe, platform) == "system" or "\\microsoft\\windows defender\\" in exe.lower()


def _threshold(value: str) -> Severity | None:
    return Severity.parse(value) if value else None


class Responder:
    """Bus subscriber. Quarantines flagged files and/or ends flagged processes when configured to."""

    def __init__(self, ctx: Context, quarantine: Quarantine | None = None) -> None:
        self.ctx = ctx
        self.quarantine = quarantine or Quarantine(ctx.data_dir)
        self.quarantine_at = _threshold(ctx.config.response.quarantine_min_severity)
        self.kill_at = _threshold(ctx.config.response.kill_min_severity)

    @property
    def enabled(self) -> bool:
        return self.quarantine_at is not None or self.kill_at is not None

    def handle(self, event: Event) -> None:
        try:
            if event.category == "file" and event.action in ("created", "renamed", "modified"):
                if self.quarantine_at is not None and event.severity >= self.quarantine_at:
                    self._quarantine(event)
            elif event.category == "process" and event.action == "started":
                if self.kill_at is not None and event.severity >= self.kill_at:
                    self._kill(event)
        except Exception:  # noqa: BLE001 - a failed response must not break alerting
            log.exception("automatic response failed")

    def _say(self, title: str, subject: str, details: dict, severity: Severity = Severity.LOW) -> None:
        self.ctx.bus.publish(make_event("system", "response", title, subject, details=details, min_severity=severity))

    def _quarantine(self, event: Event) -> None:
        path = str(event.details.get("path") or event.subject)
        name = sanitize.clean(basename(path), 120)
        try:
            record = self.quarantine.add(path, event.title, str(event.details.get("sha256") or ""))
        except QuarantineError as exc:
            self._say(f"Could not quarantine {name}: {exc}", path, {"path": path, "trigger": event.id})
            return
        if not record.original_removed:
            # It is running or locked. Keep no copy (one would pile up per attempt) and say plainly that it is still there.
            try:
                self.quarantine.delete(record.id)
            except QuarantineError:
                pass
            self._say(f"Could not remove {name}: it is in use or locked, and is still on disk", path,
                      {"path": path, "sha256": record.sha256, "trigger": event.id}, Severity.HIGH)
            return
        self.ctx.state.forget_drop(path)
        self._say(f"Quarantined {name} (id {record.id[:8]})", path,
                  {"path": path, "quarantine_id": record.id, "sha256": record.sha256, "trigger": event.id}, Severity.MEDIUM)

    def _kill(self, event: Event) -> None:
        if psutil is None:
            return
        pid = int(event.details.get("pid") or 0)
        started = float(event.details.get("create_time") or 0.0)
        name = str(event.details.get("name") or "")
        shown = sanitize.clean(name or f"pid {pid}", 80)
        exe = str(event.details.get("exe") or "")
        if pid <= 4 or pid in (os.getpid(), os.getppid()) or is_protected(name, exe, self.ctx.platform):
            self._say(f"Left {shown} running: it is a protected system process", str(pid), {"pid": pid, "trigger": event.id})
            return
        if not started:
            # Without a start time we cannot prove the process id still belongs to the same program.
            self._say(f"Could not stop {shown}: its start time is unknown, so it cannot be identified safely", str(pid),
                      {"pid": pid, "trigger": event.id}, Severity.MEDIUM)
            return
        try:
            process = psutil.Process(pid)
            if abs(process.create_time() - started) > 1.0:
                return  # the process id now belongs to a different program
            process.kill()
        except psutil.NoSuchProcess:
            return
        except (psutil.Error, OSError) as exc:
            self._say(f"Could not stop {shown}: {type(exc).__name__}", str(pid), {"pid": pid, "trigger": event.id})
            return
        self._say(f"Stopped {shown} (pid {pid})", str(pid), {"pid": pid, "name": name, "trigger": event.id}, Severity.MEDIUM)
