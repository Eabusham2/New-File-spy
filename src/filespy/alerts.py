"""Telling the user: console, log file, desktop notification, sound and webhook.

Text from the monitored machine is cleaned before it is shown, and is handed to
notification helpers as data (arguments or environment variables), never as code.
"""

from __future__ import annotations

import html
import json
import logging
import logging.handlers
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, TextIO

from filespy.config import Config
from filespy.events import Event, Severity
from filespy.sanitize import clean, json_safe

log = logging.getLogger("filespy")

_COLORS = {
    Severity.CRITICAL: "\x1b[1;97;41m", Severity.HIGH: "\x1b[1;31m", Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m", Severity.INFO: "\x1b[2m",
}
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"

_TOAST_SCRIPT = (
    "$ErrorActionPreference='Stop';"
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;"
    "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
    "$n=$t.GetElementsByTagName('text');"
    "$n.Item(0).AppendChild($t.CreateTextNode($env:FILESPY_TITLE)) | Out-Null;"
    "$n.Item(1).AppendChild($t.CreateTextNode($env:FILESPY_BODY)) | Out-Null;"
    "$toast=[Windows.UI.Notifications.ToastNotification]::new($t);"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show($toast)"
)


def enable_windows_ansi() -> bool:
    """Turn on ANSI colour handling in a Windows console. False if that is not possible."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001
        return False


def detail_line(event: Event) -> str:
    d = event.details
    parts = []
    if d.get("pid"):
        parts.append(f"pid {d['pid']}")
    if d.get("parent_name"):
        parts.append(f"started by {clean(d['parent_name'], 60)}")
    if d.get("cmdline") and event.category == "process":
        parts.append(f"command: {clean(d['cmdline'], 300)}")
    if d.get("command") and event.category == "autorun":
        parts.append(f"runs: {clean(d['command'], 300)}")
    if d.get("sha256"):
        parts.append(f"sha256 {d['sha256']}")
    if d.get("size") and event.category == "file":
        parts.append(f"{d['size']:,} bytes")
    return "   ".join(parts)


def format_event(event: Event, color: bool = False) -> str:
    """Multi-line, human-readable form of an event with every untrusted string cleaned."""
    stamp = time.strftime("%H:%M:%S", time.localtime(event.ts))
    label = f"{event.severity.name:<8}"
    if color:
        label = f"{_COLORS[event.severity]}{label}{_RESET}"
    lines = [f"{stamp}  {label}  {event.category.upper():<8} {clean(event.title, 300)}"]
    indent = " " * 10
    if event.subject and event.category != "system":
        lines.append(f"{indent}{clean(event.subject, 400)}")
    for indicator in event.indicators[:8]:
        lines.append(f"{indent}- {clean(indicator.description, 300)}")
    extra = detail_line(event)
    if extra:
        lines.append(f"{indent}{_DIM}{extra}{_RESET}" if color else f"{indent}{extra}")
    return "\n".join(lines)


class ConsoleNotifier:
    def __init__(self, min_severity: Severity, color: str = "auto", stream: TextIO | None = None, as_json: bool = False) -> None:
        self.min_severity = min_severity
        self.stream = stream or sys.stdout
        self.as_json = as_json
        is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.color = color == "always" or (color == "auto" and is_tty and enable_windows_ansi() and "NO_COLOR" not in os.environ)
        self._lock = threading.Lock()

    def __call__(self, event: Event) -> None:
        if event.severity < self.min_severity and not (event.category == "system" and event.action in ("info", "summary")):
            return
        text = json.dumps(json_safe(event.to_dict())) if self.as_json else format_event(event, self.color)
        with self._lock:
            try:
                self.stream.write(text + "\n")
            except UnicodeEncodeError:
                encoding = getattr(self.stream, "encoding", None) or "ascii"
                self.stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")
            self.stream.flush()


class LogFileNotifier:
    def __init__(self, data_dir: Path) -> None:
        folder = Path(data_dir) / "logs"
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / "filespy.log"
        self._handler = logging.handlers.RotatingFileHandler(self.path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._lock = threading.Lock()

    def __call__(self, event: Event) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts))
        reasons = "; ".join(clean(i.description, 200) for i in event.indicators)
        line = f"{stamp} {event.severity.name} {event.category}/{event.action} | {clean(event.title, 300)} | {clean(event.subject, 400)}"
        if reasons:
            line += f" | {reasons}"
        record = logging.LogRecord("filespy.events", logging.INFO, "", 0, line, None, None)
        with self._lock:
            self._handler.emit(record)

    def close(self) -> None:
        self._handler.close()


def notification_command(title: str, body: str, platform: str = sys.platform, environ: dict[str, str] | None = None) -> tuple[list[str], dict[str, str]] | None:
    """Command line and environment that shows a desktop notification, or None if unsupported.

    The text is passed as arguments or environment variables only.
    """
    environ = dict(os.environ if environ is None else environ)
    if platform == "win32":
        root = environ.get("SystemRoot") or environ.get("SYSTEMROOT") or r"C:\Windows"
        exe = root + r"\System32\WindowsPowerShell\v1.0\powershell.exe"
        environ["FILESPY_TITLE"] = title
        environ["FILESPY_BODY"] = body
        return [exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", _TOAST_SCRIPT], environ
    if platform == "darwin":
        script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
        return ["/usr/bin/osascript", "-e", script, title, body], environ
    tool = shutil.which("notify-send")
    if tool is None:
        return None
    return [tool, "--app-name=FileSpy", "--urgency=critical", "--", title, html.escape(body, quote=False)], environ


class DesktopNotifier:
    """Rate-limited so an alert storm cannot spawn hundreds of helper processes."""

    def __init__(self, min_severity: Severity, per_minute: int = 6, runner: Any = None) -> None:
        self.min_severity = min_severity
        self.per_minute = max(1, per_minute)
        self._times: deque[float] = deque()
        self._suppressed = 0
        self._lock = threading.Lock()
        self._runner = runner or self._run
        self._unsupported = False

    def __call__(self, event: Event) -> None:
        if event.severity < self.min_severity or event.category == "system" or self._unsupported:
            return
        now = time.monotonic()
        with self._lock:
            while self._times and now - self._times[0] > 60:
                self._times.popleft()
            if len(self._times) >= self.per_minute:
                self._suppressed += 1
                return
            self._times.append(now)
            extra, self._suppressed = self._suppressed, 0
        title = f"FileSpy: {event.severity.name} alert"
        body = clean(event.title, 180)
        if event.indicators:
            body += " - " + clean(event.indicators[0].description, 160)
        if extra:
            body += f" (+{extra} more alerts)"
        command = notification_command(title, body)
        if command is None:
            self._unsupported = True
            return
        threading.Thread(target=self._runner, args=command, name="filespy-notify", daemon=True).start()

    @staticmethod
    def _run(argv: list[str], environ: dict[str, str]) -> None:
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(argv, env=environ, timeout=20, check=False, stdin=subprocess.DEVNULL,  # noqa: S603
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        except (OSError, subprocess.SubprocessError) as exc:
            log.debug("desktop notification failed: %s", exc)


def beep() -> None:
    try:
        if os.name == "nt":
            import winsound

            winsound.MessageBeep(winsound.MB_ICONHAND)
        elif sys.stderr.isatty():
            sys.stderr.write("\a")
            sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass


def webhook_allowed(url: str) -> bool:
    """HTTPS anywhere, or plain HTTP to this computer only."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")


class WebhookNotifier:
    """Posts alerts as JSON from a background thread; drops alerts rather than block or pile up."""

    def __init__(self, url: str, min_severity: Severity) -> None:
        self.url = url
        self.min_severity = min_severity
        self._queue: queue.Queue[Event | None] = queue.Queue(maxsize=200)
        self._thread = threading.Thread(target=self._worker, name="filespy-webhook", daemon=True)
        self._thread.start()

    def __call__(self, event: Event) -> None:
        if event.severity >= self.min_severity and event.category != "system":
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                pass

    @staticmethod
    def payload(event: Event) -> dict[str, Any]:
        text = f"[{event.severity.name}] {clean(event.title, 300)}"
        if event.subject:
            text += f"\n{clean(event.subject, 400)}"
        for indicator in event.indicators[:5]:
            text += f"\n- {clean(indicator.description, 200)}"
        return {"text": text, "content": text[:1900], "event": json_safe(event.to_dict())}

    def _worker(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            try:
                request = urllib.request.Request(  # noqa: S310 - scheme checked by webhook_allowed
                    self.url, data=json.dumps(self.payload(event)).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "FileSpy"}, method="POST",
                )
                with urllib.request.urlopen(request, timeout=8) as response:  # noqa: S310
                    response.read(1024)
            except Exception as exc:  # noqa: BLE001
                log.debug("webhook delivery failed: %s", exc)

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass


class AlertManager:
    """Bus subscriber that fans an event out to every enabled channel."""

    def __init__(self, cfg: Config, data_dir: Path, stream: TextIO | None = None, console: bool = True, as_json: bool = False) -> None:
        alerts = cfg.alerts
        self.channels: list[Any] = []
        self.warnings: list[str] = []
        if console and alerts.console:
            self.channels.append(ConsoleNotifier(Severity.parse(cfg.general.min_severity), alerts.color, stream, as_json))
        if alerts.log_file:
            try:
                self.channels.append(LogFileNotifier(data_dir))
            except OSError as exc:
                self.warnings.append(f"log file disabled: {exc}")
        if alerts.desktop:
            self.channels.append(DesktopNotifier(Severity.parse(alerts.desktop_min_severity), alerts.max_desktop_per_minute))
        if alerts.webhook_url:
            if webhook_allowed(alerts.webhook_url):
                self.channels.append(WebhookNotifier(alerts.webhook_url, Severity.parse(alerts.webhook_min_severity)))
            else:
                self.warnings.append("webhook disabled: the address must use https (plain http is allowed only for localhost)")
        self._sound = alerts.sound
        self._sound_min = Severity.parse(alerts.desktop_min_severity)

    def handle(self, event: Event) -> None:
        for channel in self.channels:
            try:
                channel(event)
            except Exception:  # noqa: BLE001 - one broken channel must not silence the others
                log.exception("alert channel %r failed", channel)
        if self._sound and event.severity >= self._sound_min and event.category != "system":
            beep()

    def close(self) -> None:
        for channel in self.channels:
            closer = getattr(channel, "close", None)
            if closer:
                closer()
