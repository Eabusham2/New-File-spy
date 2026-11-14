"""FileSpy's window: start and stop watching, see alerts as they happen, export, audit, settings.

Built on Tkinter from the standard library, so the Windows executable needs nothing else.
The logic (EventLog, Controller) is kept apart from the widgets so that it can be tested
without a display. Everything shown comes through ``filespy.sanitize`` first.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filespy import __version__, sanitize, virustotal
from filespy.config import Config, config_path, load_config, save_config
from filespy.events import Event, Severity
from filespy.paths import data_dir as default_data_dir
from filespy.paths import ensure_private_dir

MAX_EVENTS = 5000
MAX_ROWS = 2000
MAX_FILES = 20000
FILTERS = (
    ("Low and above", Severity.LOW), ("Medium and above", Severity.MEDIUM), ("High and above", Severity.HIGH),
    ("Critical only", Severity.CRITICAL), ("Everything", Severity.INFO),
)
EXPORT_TYPES = (("HTML report", "*.html"), ("JSON", "*.json"), ("CSV spreadsheet", "*.csv"),
                ("ZIP with everything", "*.zip"), ("JSON Lines", "*.jsonl"))
#: severity -> (text colour, row background)
ROW_COLORS = {
    "critical": ("#ffffff", "#b3123d"), "high": ("#7a1f00", "#ffe0d1"), "medium": ("#5c4300", "#fff3c4"),
    "low": ("#123a63", "#e7f1ff"), "info": ("#5c6676", "#ffffff"),
}
_DETAIL_LABELS = (
    ("path", "File"), ("exe", "Program"), ("kind", "File type"), ("size", "Size in bytes"), ("sha256", "SHA-256"),
    ("md5", "MD5"), ("pid", "Process id"), ("user", "User"), ("parent_name", "Started by"), ("cmdline", "Command line"),
    ("command", "Runs"), ("target", "Starts"), ("previous_command", "Previously"), ("old", "Was"), ("new", "Now"),
    ("remote_address", "Remote address"), ("remote_port", "Remote port"), ("local_port", "Local port"),
    ("renamed_from", "Renamed from"), ("quarantine_id", "Quarantine id"),
)


def row_for(event: Event) -> tuple[str, str, str, str]:
    """The four cells of the list row for an event, safe to display."""
    stamp = time.strftime("%H:%M:%S", time.localtime(event.ts))
    return stamp, event.severity.name, sanitize.clean(event.category, 20), sanitize.clean(event.title, 300)


def details_for(event: Event) -> str:
    """Everything known about an event as plain text, with untrusted strings made harmless."""
    clean = sanitize.clean
    lines = [clean(event.title, 400), ""]
    lines.append(f"Severity: {event.severity.name}    Score: {event.score}    Type: {clean(event.category, 20)} / {clean(event.action, 20)}")
    lines.append("When: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts)))
    if event.subject:
        lines.append("Where: " + clean(event.subject, 600))
    if event.indicators:
        lines += ["", "Why it was flagged:"]
        for indicator in event.indicators:
            extra = f"+{indicator.score}" + (f", {clean(indicator.mitre, 20)}" if indicator.mitre else "")
            lines.append(f"  - {clean(indicator.description, 300)}  ({extra})")
    shown = []
    for key, label in _DETAIL_LABELS:
        value = event.details.get(key)
        if value not in (None, "", [], {}) and not (key == "path" and value == event.subject):
            shown.append(f"  {label}: {clean(value, 600)}")
    added = event.details.get("added_lines")
    if isinstance(added, list) and added:
        shown.append("  Added lines:")
        shown += [f"    {clean(line, 300)}" for line in added[:10]]
    if shown:
        lines += ["", "Details:"] + shown
    return "\n".join(lines)


class EventLog:
    """The events of this window, newest last, with the counts shown in the status bar."""

    def __init__(self, limit: int = MAX_EVENTS) -> None:
        self.events: deque[Event] = deque(maxlen=limit)
        self.counts: Counter[str] = Counter()

    def add(self, event: Event) -> None:
        self.events.append(event)
        if event.category != "system":
            self.counts[event.severity.label] += 1

    @staticmethod
    def matches(event: Event, minimum: Severity, needle: str = "") -> bool:
        important_notice = event.category == "system" and event.action in ("warning", "error", "response")
        if event.severity < minimum and not important_notice:
            return False
        return not needle or needle in f"{event.title} {event.subject} {event.category}".lower()

    def visible(self, minimum: Severity, text: str = "") -> list[Event]:
        """Events to show, newest first."""
        needle = text.strip().lower()
        return [event for event in reversed(self.events) if self.matches(event, minimum, needle)]

    def clear(self) -> None:
        self.events.clear()
        self.counts.clear()

    def summary(self) -> str:
        return "    ".join(f"{s.name.capitalize()} {self.counts[s.label]}" for s in reversed(Severity))


FILE_STATUS = {"created": "New", "renamed": "Renamed", "modified": "Changed", "deleted": "Deleted"}
KIND_NAMES = {
    "pe": "Windows program", "elf": "Linux program", "macho": "Mac program", "script": "Script", "lnk": "Shortcut",
    "ole": "Installer / Office", "html": "Web page / HTA", "zip": "Archive", "rar": "Archive", "7z": "Archive",
    "cab": "Archive", "pdf": "PDF", "text": "Text", "data": "Data", "empty": "Empty", "javaclass": "Java class",
}


def human_size(size: Any) -> str:
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        return ""
    if size < 1024:
        return f"{size:,} bytes"
    value = float(size)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024
        if value < 1024 or unit == "TB":
            return f"{value:,.1f} {unit}"
    return ""


@dataclass
class FileEntry:
    """One file seen during the session, as shown on the Files tab."""

    path: str
    status: str
    event: Event  # the event with the latest examination of the file
    severity: Severity
    ts: float
    sha256: str = ""
    kind: str = ""
    size: Any = None
    history: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]

    @property
    def folder(self) -> str:
        cut = max(self.path.rfind("/"), self.path.rfind("\\"))
        return self.path[:cut] if cut > 0 else ""

    def row(self) -> tuple[str, ...]:
        """The cells of the Files tab, safe to display."""
        clean = sanitize.clean
        return (
            time.strftime("%H:%M:%S", time.localtime(self.ts)), self.status, clean(self.name, 120),
            KIND_NAMES.get(self.kind, clean(self.kind, 20)), human_size(self.size), self.severity.name,
            "Check / Upload", clean(self.folder, 300),
        )


class FileList:
    """Every file seen this session, one entry per path, newest last."""

    def __init__(self, limit: int = MAX_FILES) -> None:
        self.items: OrderedDict[str, FileEntry] = OrderedDict()
        self.limit = limit

    @staticmethod
    def key(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    def note(self, event: Event) -> FileEntry | None:
        """Record what an event says about a file; returns the entry it changed, if any."""
        details = event.details
        if event.category == "system" and event.action == "response" and details.get("quarantine_id"):
            entry = self.items.get(self.key(str(details.get("path") or "")))
            if entry is not None:
                entry.status = "Quarantined"
                entry.history.append("Quarantined")
            return entry
        if event.category != "file" or event.action not in FILE_STATUS:
            return None
        path = str(details.get("path") or event.subject or "")
        if not path:
            return None
        key = self.key(path)
        entry = self.items.pop(key, None)
        status = FILE_STATUS[event.action]
        if entry is None:
            entry = FileEntry(path=path, status=status, event=event, severity=event.severity, ts=event.ts)
        else:
            entry.status, entry.ts = status, event.ts
        entry.history.append(status)
        if event.action == "deleted":
            entry.severity = max(entry.severity, event.severity)  # a dangerous file stays marked after it is gone
        else:
            entry.event, entry.severity = event, event.severity
            entry.sha256 = str(details.get("sha256") or entry.sha256)
            entry.kind = str(details.get("kind") or entry.kind)
            entry.size = details.get("size", entry.size)
        self.items[key] = entry
        while len(self.items) > self.limit:
            self.items.popitem(last=False)
        return entry

    def visible(self, text: str = "") -> list[FileEntry]:
        """Entries to show, newest first, optionally only those mentioning ``text``."""
        needle = text.strip().lower()
        return [e for e in reversed(self.items.values())
                if not needle or needle in f"{e.path} {e.status} {e.kind} {e.sha256}".lower()]

    def get(self, path: str) -> FileEntry | None:
        return self.items.get(self.key(path))

    def clear(self) -> None:
        self.items.clear()


class Controller:
    """Runs the monitoring engine for the window. Has no dependency on Tk."""

    def __init__(self, data_dir: str | os.PathLike[str] | None = None, config_file: str | os.PathLike[str] | None = None) -> None:
        self.data_dir = ensure_private_dir(Path(data_dir) if data_dir else default_data_dir())
        self.config_file = Path(config_file) if config_file else config_path(self.data_dir)
        self.config: Config = load_config(self.config_file)
        self.queue: queue.Queue[Event] = queue.Queue()
        self.log = EventLog()
        self.files = FileList()
        self.changed: deque[FileEntry] = deque(maxlen=MAX_ROWS)  # Files-tab entries to redraw
        self.app: Any = None
        self.state = "stopped"  # stopped | starting | watching | stopping
        self.error = ""
        self.session = ""
        self.monitors: list[str] = []
        self.last_exports: list[Path] = []
        self._lock = threading.Lock()

    # -- watching ---------------------------------------------------------------
    def start(self) -> bool:
        with self._lock:
            if self.state != "stopped":
                return False
            self.state = "starting"
        self.error = ""
        threading.Thread(target=self._start, name="filespy-gui-start", daemon=True).start()
        return True

    def _start(self) -> None:
        try:
            from filespy.app import App

            self.config = load_config(self.config_file)
            app = App(self.config, self.data_dir, console=False)
            app.bus.subscribe(self.queue.put)
            app.start()
            self.app, self.session = app, app.session
            self.monitors = [n for n, m in zip(app.monitor_names, app.monitors) if not m.failed]
            self.state = "watching"
        except Exception as exc:  # noqa: BLE001 - shown to the user instead of crashing the window
            self.error = f"{type(exc).__name__}: {exc}"
            self.state = "stopped"

    def stop(self) -> bool:
        with self._lock:
            if self.state != "watching":
                return False
            self.state = "stopping"
        threading.Thread(target=self._stop, name="filespy-gui-stop", daemon=True).start()
        return True

    def _stop(self) -> None:
        try:
            self.last_exports = self.app.stop()
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.app = None
            self.state = "stopped"

    def drain(self, limit: int = 500) -> list[Event]:
        """Move newly published events into the log and return them (oldest first)."""
        fresh: list[Event] = []
        while len(fresh) < limit:
            try:
                event = self.queue.get_nowait()
            except queue.Empty:
                break
            self.log.add(event)
            entry = self.files.note(event)
            if entry is not None:
                self.changed.append(entry)
            fresh.append(event)
        return fresh

    # -- actions ----------------------------------------------------------------
    def export(self, fmt: str, destination: str | os.PathLike[str]) -> tuple[Path, int]:
        """Export this session (or, before any session, the last day) and return (file, number of events)."""
        from filespy.export import export_events, filter_events
        from filespy.storage import EventStore

        store = EventStore(self.data_dir / "events.db")
        try:
            events = store.query(session=self.session) if self.session else store.query(since=time.time() - 86400)
        finally:
            store.close()
        selected = filter_events(events, self.config)
        return export_events(selected, fmt, destination, self.config, {"session": self.session}), len(selected)

    def audit(self) -> list[dict[str, Any]]:
        from filespy.cli import collect_audit
        from filespy.context import Context
        from filespy.events import EventBus
        from filespy.registry import make_registry

        app = self.app
        ctx = app.ctx if app is not None else Context(self.config, EventBus("gui"), self.data_dir, registry=make_registry())
        return collect_audit(ctx)

    def quarantine(self, path: str, sha256: str = "") -> Any:
        from filespy.quarantine import Quarantine

        return Quarantine(self.data_dir).add(path, "from the FileSpy window", sha256)

    def save_config(self) -> None:
        self.config.validate()
        save_config(self.config, self.config_file)


def audit_text(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "Nothing suspicious was found in the current autostart entries, settings or running programs."
    lines = []
    for item in findings:
        lines.append(f"{str(item['severity']).upper():<9} {item['area']:<8} {sanitize.clean(item['title'], 200)}")
        lines.append(f"          {sanitize.clean(item['subject'], 300)}")
        lines += [f"          - {sanitize.clean(reason, 300)}" for reason in item["reasons"]]
        lines.append("")
    lines.append(f"{len(findings)} finding(s). These are things worth a look, not proof of infection.")
    return "\n".join(lines)


def open_folder(folder: str) -> bool:
    """Show a folder in the file manager. Only ever given a directory, never a file to run."""
    if not os.path.isdir(folder):
        return False
    try:
        if os.name == "nt":
            os.startfile(folder)  # type: ignore[attr-defined]  # noqa: S606 - a directory, checked above
        elif sys.platform == "darwin":
            subprocess.Popen(["/usr/bin/open", folder])  # noqa: S603
        else:
            tool = shutil.which("xdg-open")
            if tool is None:
                return False
            subprocess.Popen([tool, folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
        return True
    except OSError:
        return False


def relaunch_as_admin(arguments: list[str] | None = None) -> bool:
    """Windows: start another copy elevated (the user sees the usual consent prompt)."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        forwarded = [*(arguments or []), "--elevated"]
        if getattr(sys, "frozen", False):
            program, parameters = sys.executable, forwarded
        else:
            program, parameters = sys.executable, ["-m", "filespy.gui", *forwarded]
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, subprocess.list2cmdline(parameters), None, 1)  # type: ignore[attr-defined]
        return int(result) > 32
    except Exception:  # noqa: BLE001
        return False


class MainWindow:
    """The Tk window. All work happens in the Controller; this class only shows it."""

    POLL_MS = 250

    def __init__(self, root: Any, controller: Controller, autostart: bool = False) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root, self.ctl = root, controller
        self.rows: dict[str, Event] = {}
        self.file_items: dict[str, str] = {}  # file key -> Files tab item
        self.item_files: dict[str, FileEntry] = {}  # Files tab item -> entry
        self.jobs: list[dict[str, Any]] = []  # VirusTotal work running in the background
        self._last_state = ""
        self._audit: dict[str, Any] | None = None
        self._closing = False
        self._build()
        self._update_status()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(self.POLL_MS, self._tick)
        if autostart:
            self.toggle()

    # -- layout -----------------------------------------------------------------
    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        root = self.root
        root.title(f"FileSpy {__version__}")
        root.geometry("1120x720")
        root.minsize(860, 520)
        style = ttk.Style(root)
        for theme in ("vista", "aqua", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Treeview", rowheight=24)

        top = ttk.Frame(root, padding=(10, 10, 10, 6))
        top.pack(fill="x")
        self.toggle_button = ttk.Button(top, text="Start watching", width=18, command=self.toggle)
        self.toggle_button.pack(side="left")
        ttk.Button(top, text="Export report...", command=self.export).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Check this PC now", command=self.audit).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Settings...", command=self.settings).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Open data folder", command=lambda: open_folder(str(self.ctl.data_dir))).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="About", command=self.about).pack(side="right")
        from filespy.app import is_admin

        self.admin = is_admin()
        if os.name == "nt" and not self.admin:
            ttk.Button(top, text="Restart as administrator", command=self.elevate).pack(side="right", padx=(0, 8))

        status = ttk.Frame(root, padding=(10, 0, 10, 6))
        status.pack(fill="x")
        self.status = tk.StringVar()
        ttk.Label(status, textvariable=self.status).pack(side="left")
        self.counts = tk.StringVar()
        ttk.Label(status, textvariable=self.counts).pack(side="right")

        bar = ttk.Frame(root, padding=(10, 0, 10, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Show:").pack(side="left")
        self.level = tk.StringVar(value=FILTERS[0][0])
        chooser = ttk.Combobox(bar, textvariable=self.level, values=[name for name, _ in FILTERS], state="readonly", width=18)
        chooser.pack(side="left", padx=(4, 12))
        chooser.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        ttk.Label(bar, text="Find:").pack(side="left")
        self.find = tk.StringVar()
        self.find.trace_add("write", lambda *_a: self.refresh())
        ttk.Entry(bar, textvariable=self.find, width=36).pack(side="left", padx=(4, 12))
        ttk.Button(bar, text="Clear list", command=self.clear).pack(side="left")

        panes = ttk.Panedwindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.notebook = ttk.Notebook(panes)
        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._show_selected())
        upper = ttk.Frame(self.notebook)
        self.tree = ttk.Treeview(upper, columns=("time", "severity", "type", "what"), show="headings", selectmode="browse")
        for column, title, width, stretch in (("time", "Time", 80, False), ("severity", "Severity", 90, False),
                                              ("type", "Type", 90, False), ("what", "What happened", 760, True)):
            self.tree.heading(column, text=title, anchor="w")
            self.tree.column(column, width=width, stretch=stretch, anchor="w")
        for name, (foreground, background) in ROW_COLORS.items():
            self.tree.tag_configure(name, foreground=foreground, background=background)
        scroll = ttk.Scrollbar(upper, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_selected())
        self.notebook.add(upper, text="Alerts")
        self._build_files_tab()
        panes.add(self.notebook, weight=3)

        lower = ttk.Frame(panes)
        actions = ttk.Frame(lower)
        actions.pack(fill="x", pady=(6, 4))
        ttk.Label(actions, text="Details of the selected item").pack(side="left")
        ttk.Button(actions, text="Quarantine this file", command=self.quarantine_selected).pack(side="right")
        ttk.Button(actions, text="Open containing folder", command=self.open_selected_folder).pack(side="right", padx=(0, 8))
        ttk.Button(actions, text="Copy details", command=self.copy_details).pack(side="right", padx=(0, 8))
        ttk.Button(actions, text="Upload to VirusTotal...", command=self.upload_virustotal).pack(side="right", padx=(0, 8))
        ttk.Button(actions, text="Look up on VirusTotal", command=self.lookup_virustotal).pack(side="right", padx=(0, 8))
        self.details = tk.Text(lower, height=11, wrap="word", state="disabled", relief="solid", borderwidth=1, padx=8, pady=6)
        detail_scroll = ttk.Scrollbar(lower, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=detail_scroll.set)
        self.details.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")
        panes.add(lower, weight=2)
        self._build_menus()

    # -- the list ---------------------------------------------------------------
    def _minimum(self) -> Severity:
        return dict(FILTERS).get(self.level.get(), Severity.LOW)

    def _insert(self, event: Event, index: Any) -> None:
        item = self.tree.insert("", index, values=row_for(event), tags=(event.severity.label,))
        self.rows[item] = event

    def _add_rows(self, fresh: list[Event]) -> None:
        minimum, needle = self._minimum(), self.find.get().strip().lower()
        for event in fresh:
            if EventLog.matches(event, minimum, needle):
                self._insert(event, 0)
        for item in self.tree.get_children()[MAX_ROWS:]:
            self.tree.delete(item)
            self.rows.pop(item, None)
        while self.ctl.changed:
            self._place_file(self.ctl.changed.popleft(), 0)

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        for event in self.ctl.log.visible(self._minimum(), self.find.get())[:MAX_ROWS]:
            self._insert(event, "end")
        self.files_tree.delete(*self.files_tree.get_children())
        self.file_items.clear()
        self.item_files.clear()
        for entry in self.ctl.files.visible(self.find.get())[:MAX_ROWS]:
            self._place_file(entry, "end")
        self._set_details("")

    def clear(self) -> None:
        self.ctl.log.clear()
        self.ctl.files.clear()
        self.refresh()
        self._update_status()

    def selected(self) -> Event | None:
        if self.on_files_tab():
            entry = self.selected_file()
            return entry.event if entry else None
        chosen = self.tree.selection()
        return self.rows.get(chosen[0]) if chosen else None

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _show_selected(self) -> None:
        entry = self.selected_file() if self.on_files_tab() else None
        if entry is not None:
            history = " > ".join(entry.history[-6:])
            self._set_details(f"Status: {entry.status}    History this session: {history}\n\n{details_for(entry.event)}")
            return
        event = self.selected()
        self._set_details(details_for(event) if event else "")

    # -- status -----------------------------------------------------------------
    def _update_status(self) -> None:
        state = self.ctl.state
        labels = {"stopped": "Start watching", "starting": "Starting...", "watching": "Stop watching", "stopping": "Stopping..."}
        self.toggle_button.configure(text=labels[state], state="normal" if state in ("stopped", "watching") else "disabled")
        if state == "starting":
            text = "Taking a baseline of the current state. What already exists is not an alert."
        elif state == "watching":
            text = "Watching: " + ", ".join(self.ctl.monitors or ["nothing"])
            if not self.admin:
                text += "    (not administrator: other users' programs and some system locations are not visible)"
        elif state == "stopping":
            text = "Stopping..."
        elif self.ctl.error:
            text = "Could not watch: " + sanitize.clean(self.ctl.error, 300)
        elif self.ctl.last_exports:
            text = "Not watching. Report saved: " + ", ".join(str(p) for p in self.ctl.last_exports[:2])
        else:
            text = "Not watching. Press Start watching, then run or open whatever you want to observe."
        self.status.set(text)
        self.counts.set(f"{len(self.ctl.files.items)} files    " + self.ctl.log.summary())
        self._last_state = state

    def _tick(self) -> None:
        fresh = self.ctl.drain()
        if fresh:
            self._add_rows(fresh)
        if fresh or self.ctl.state != self._last_state:
            self._update_status()
        if self._audit is not None and self._audit.get("done"):
            job, self._audit = self._audit, None
            self._show_text("Check of this PC", job.get("text", ""))
        self._finish_jobs()
        if self._closing and self.ctl.state == "stopped":
            self.dispose()
            return
        self.root.after(self.POLL_MS, self._tick)

    # -- commands ---------------------------------------------------------------
    def toggle(self) -> None:
        if self.ctl.state == "stopped":
            self.ctl.start()
        elif self.ctl.state == "watching":
            self.ctl.stop()
        self._update_status()

    def export(self) -> None:
        from tkinter import filedialog, messagebox

        name = f"filespy-report-{time.strftime('%Y%m%d-%H%M%S')}.html"
        target = filedialog.asksaveasfilename(parent=self.root, title="Export report", defaultextension=".html",
                                              initialfile=name, filetypes=list(EXPORT_TYPES))
        if not target:
            return
        fmt = Path(target).suffix.lstrip(".").lower() or "html"
        try:
            written, count = self.ctl.export(fmt, target)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return
        messagebox.showinfo("Export finished", f"{count} event(s) written to\n{written}", parent=self.root)

    def audit(self) -> None:
        if self._audit is not None:
            return
        job: dict[str, Any] = {"done": False}
        self._audit = job

        def work() -> None:
            try:
                job["text"] = audit_text(self.ctl.audit())
            except Exception as exc:  # noqa: BLE001
                job["text"] = f"The check could not be completed: {type(exc).__name__}: {exc}"
            job["done"] = True

        threading.Thread(target=work, name="filespy-gui-audit", daemon=True).start()
        self.status.set("Checking current autostart entries, settings and running programs...")

    def _show_text(self, title: str, text: str) -> Any:
        tk, ttk = self.tk, self.ttk
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("900x520")
        box = tk.Text(window, wrap="word", padx=10, pady=8)
        scroll = ttk.Scrollbar(window, orient="vertical", command=box.yview)
        box.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        box.pack(fill="both", expand=True)
        box.insert("1.0", text)
        box.configure(state="disabled")
        self._update_status()
        return window

    def copy_details(self) -> None:
        event = self.selected()
        if event is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append(details_for(event))

    def _selected_path(self) -> str:
        if self.on_files_tab():
            entry = self.selected_file()
            return entry.path if entry else ""
        event = self.selected()
        if event is None:
            return ""
        for key in ("path", "exe", "target"):
            value = event.details.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def open_selected_folder(self) -> None:
        from tkinter import messagebox

        path = self._selected_path()
        if not path or not open_folder(os.path.dirname(path)):
            messagebox.showinfo("Open folder", "This alert has no folder that can be opened.", parent=self.root)

    def quarantine_selected(self) -> None:
        from tkinter import messagebox

        from filespy.quarantine import QuarantineError

        event = self.selected()
        path = str(event.details.get("path") or "") if event is not None and event.category == "file" else ""
        if not path:
            messagebox.showinfo("Quarantine", "Select a file alert first.", parent=self.root)
            return
        shown = sanitize.clean(path, 300)
        if not messagebox.askyesno("Quarantine", f"Move this file into quarantine so it cannot run?\n\n{shown}\n\n"
                                   "You can restore it later with: filespy quarantine restore", parent=self.root):
            return
        try:
            record = self.ctl.quarantine(path, str(event.details.get("sha256") or ""))
        except QuarantineError as exc:
            messagebox.showerror("Quarantine", str(exc), parent=self.root)
            return
        if record.original_removed:
            messagebox.showinfo("Quarantine", f"Quarantined (id {record.id[:12]}).", parent=self.root)
            entry = self.ctl.files.get(path)
            if entry is not None:
                entry.status = "Quarantined"
                entry.history.append("Quarantined")
                self._place_file(entry, 0)
        else:
            messagebox.showwarning("Quarantine", "A copy was stored, but the original is in use and could not be removed.", parent=self.root)

    def settings(self) -> Any:
        tk, ttk = self.tk, self.ttk
        from tkinter import filedialog

        cfg = self.ctl.config
        window = tk.Toplevel(self.root)
        window.title("Settings")
        window.resizable(False, False)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Extra folders to watch").grid(row=0, column=0, columnspan=2, sticky="w")
        folders = tk.Listbox(frame, height=5, width=70)
        for folder in cfg.files.paths:
            folders.insert("end", folder)
        folders.grid(row=1, column=0, columnspan=2, sticky="we", pady=(2, 4))

        def add_folder() -> None:
            chosen = filedialog.askdirectory(parent=window, title="Folder to watch")
            if chosen and chosen not in folders.get(0, "end"):
                folders.insert("end", chosen)

        def remove_folder() -> None:
            for index in reversed(folders.curselection()):
                folders.delete(index)

        ttk.Button(frame, text="Add folder...", command=add_folder).grid(row=2, column=0, sticky="w")
        ttk.Button(frame, text="Remove selected", command=remove_folder).grid(row=2, column=1, sticky="w")
        flags = {}
        options = (
            ("Watch the standard drop locations (Temp, AppData, Downloads, Startup...)", "files", "use_default_paths"),
            ("List every new file on the Files tab, not only programs and scripts", "files", "report_all"),
            ("Show a desktop notification for serious alerts", "alerts", "desktop"),
            ("Play a sound for serious alerts", "alerts", "sound"),
            ("Save a report automatically when watching stops", "export", "auto_on_exit"),
        )
        for offset, (label, section, key) in enumerate(options):
            flags[(section, key)] = tk.BooleanVar(value=bool(getattr(getattr(cfg, section), key)))
            ttk.Checkbutton(frame, text=label, variable=flags[(section, key)]).grid(row=3 + offset, column=0, columnspan=2, sticky="w", pady=(6 if offset == 0 else 0, 0))
        base = 3 + len(options)
        choices = ("Never", "Critical", "High")
        ttk.Label(frame, text="Quarantine a dropped file automatically at:").grid(row=base, column=0, sticky="w", pady=(10, 0))
        quarantine = tk.StringVar(value=(cfg.response.quarantine_min_severity or "never").capitalize())
        ttk.Combobox(frame, textvariable=quarantine, values=choices, state="readonly", width=12).grid(row=base, column=1, sticky="w", pady=(10, 0))
        ttk.Label(frame, text="Stop a flagged program automatically at:").grid(row=base + 1, column=0, sticky="w")
        kill = tk.StringVar(value=(cfg.response.kill_min_severity or "never").capitalize())
        ttk.Combobox(frame, textvariable=kill, values=choices, state="readonly", width=12).grid(row=base + 1, column=1, sticky="w")
        ttk.Label(frame, text="VirusTotal API key (optional, for one-click uploads):").grid(row=base + 2, column=0, sticky="w", pady=(10, 0))
        vt_key = tk.StringVar(value=cfg.detection.virustotal_api_key)
        ttk.Entry(frame, textvariable=vt_key, show="*", width=30).grid(row=base + 2, column=1, sticky="w", pady=(10, 0))
        ttk.Label(frame, text="Get a free key by signing in at virustotal.com. It is kept in FileSpy's settings and left out of exports.",
                  foreground="#5c6676").grid(row=base + 3, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Changes apply the next time you start watching. Automatic actions are off unless you choose a level.",
                  foreground="#5c6676").grid(row=base + 4, column=0, columnspan=2, sticky="w", pady=(10, 6))

        def save() -> None:
            cfg.files.paths = list(folders.get(0, "end"))
            for (section, key), variable in flags.items():
                setattr(getattr(cfg, section), key, bool(variable.get()))
            cfg.response.quarantine_min_severity = "" if quarantine.get() == "Never" else quarantine.get().lower()
            cfg.response.kill_min_severity = "" if kill.get() == "Never" else kill.get().lower()
            cfg.detection.virustotal_api_key = vt_key.get().strip()
            self.ctl.save_config()
            finish()

        def finish() -> None:
            # Break the window -> save -> variables cycle so the variables are freed now, on this
            # thread; Tk variables freed later by a background thread print errors.
            window.save = window.vt_key = None  # type: ignore[attr-defined]
            window.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=base + 5, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Cancel", command=finish).pack(side="right")
        window.protocol("WM_DELETE_WINDOW", finish)
        ttk.Button(buttons, text="Save", command=save).pack(side="right", padx=(0, 8))
        window.save = save  # type: ignore[attr-defined]  # lets tests press Save
        window.vt_key = vt_key  # type: ignore[attr-defined]
        return window

    # -- the Files tab --------------------------------------------------------------
    VT_COLUMN = "#7"  # the "VirusTotal" column of the Files tab

    def _build_files_tab(self) -> None:
        ttk = self.ttk
        frame = ttk.Frame(self.notebook)
        columns = (("time", "Time", 75, False), ("status", "Status", 90, False), ("file", "File", 230, False),
                   ("type", "Type", 140, False), ("size", "Size", 90, False), ("severity", "Severity", 80, False),
                   ("vt", "VirusTotal", 110, False), ("folder", "Folder", 420, True))
        self.files_tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for column, title, width, stretch in columns:
            self.files_tree.heading(column, text=title, anchor="w")
            self.files_tree.column(column, width=width, stretch=stretch, anchor="w")
        for name, (foreground, background) in ROW_COLORS.items():
            self.files_tree.tag_configure(name, foreground=foreground, background=background)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=scroll.set)
        self.files_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.files_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_selected())
        self.files_tree.bind("<ButtonRelease-1>", self._files_click)
        self.files_tree.bind("<Double-1>", lambda _e: self.lookup_virustotal())
        self.notebook.add(frame, text="Files (all new files)")

    def _build_menus(self) -> None:
        tk = self.tk
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Look up on VirusTotal (sends only the hash)", command=self.lookup_virustotal)
        self.menu.add_command(label="Upload to VirusTotal...", command=self.upload_virustotal)
        self.menu.add_separator()
        self.menu.add_command(label="Open containing folder", command=self.open_selected_folder)
        self.menu.add_command(label="Copy path", command=self.copy_path)
        self.menu.add_command(label="Copy details", command=self.copy_details)
        self.menu.add_separator()
        self.menu.add_command(label="Quarantine this file", command=self.quarantine_selected)
        self.vt_menu = tk.Menu(self.root, tearoff=0)
        self.vt_menu.add_command(label="Look up on VirusTotal (sends only the hash)", command=self.lookup_virustotal)
        self.vt_menu.add_command(label="Upload to VirusTotal...", command=self.upload_virustotal)
        buttons = ("<Button-3>", "<Button-2>") if sys.platform == "darwin" else ("<Button-3>",)
        for tree in (self.tree, self.files_tree):
            for button in buttons:
                tree.bind(button, lambda event, t=tree: self._popup(t, event, self.menu))

    def _popup(self, tree: Any, event: Any, menu: Any) -> None:
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        tree.focus(row)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _files_click(self, event: Any) -> None:
        """A click in the VirusTotal column offers the VirusTotal actions for that file."""
        if self.files_tree.identify("region", event.x, event.y) != "cell":
            return
        if self.files_tree.identify_column(event.x) == self.VT_COLUMN:
            self._popup(self.files_tree, event, self.vt_menu)

    def _place_file(self, entry: FileEntry, index: Any) -> None:
        """Show a file's current state as one row of the Files tab (newest at the top)."""
        key = FileList.key(entry.path)
        old = self.file_items.pop(key, None)
        if old is not None:
            self.files_tree.delete(old)
            self.item_files.pop(old, None)
        needle = self.find.get().strip().lower()
        if needle and needle not in f"{entry.path} {entry.status} {entry.kind} {entry.sha256}".lower():
            return
        item = self.files_tree.insert("", index, values=entry.row(), tags=(entry.severity.label,))
        self.file_items[key] = item
        self.item_files[item] = entry
        for extra in self.files_tree.get_children()[MAX_ROWS:]:
            self.files_tree.delete(extra)
            gone = self.item_files.pop(extra, None)
            if gone is not None:
                self.file_items.pop(FileList.key(gone.path), None)

    def on_files_tab(self) -> bool:
        try:
            return self.notebook.index(self.notebook.select()) == 1
        except self.tk.TclError:
            return False

    def selected_file(self) -> FileEntry | None:
        chosen = self.files_tree.selection()
        return self.item_files.get(chosen[0]) if chosen else None

    def _selected_sha256(self) -> str:
        if self.on_files_tab():
            entry = self.selected_file()
            return entry.sha256 if entry else ""
        event = self.selected()
        return str(event.details.get("sha256") or "") if event is not None else ""

    def copy_path(self) -> None:
        path = self._selected_path()
        if path:
            self.root.clipboard_clear()
            self.root.clipboard_append(path)

    # -- VirusTotal -------------------------------------------------------------------
    def _run_job(self, kind: str, path: str, work: Any) -> dict[str, Any]:
        job: dict[str, Any] = {"kind": kind, "path": path, "done": False}

        def run() -> None:
            try:
                job["result"] = work()
            except (virustotal.VirusTotalError, OSError) as exc:
                job["error"] = str(exc)
            except Exception as exc:  # noqa: BLE001 - shown to the user instead of lost in a thread
                job["error"] = f"{type(exc).__name__}: {exc}"
            job["done"] = True

        self.jobs.append(job)
        threading.Thread(target=run, name=f"filespy-gui-{kind}", daemon=True).start()
        return job

    def _finish_jobs(self) -> None:
        from tkinter import messagebox

        for job in [j for j in self.jobs if j["done"]]:
            self.jobs.remove(job)
            name = sanitize.clean(os.path.basename(job["path"]), 120)
            if "error" in job:
                self.status.set(f"VirusTotal: {sanitize.clean(job['error'], 200)}")
                messagebox.showerror("VirusTotal", f"{name}\n\n{job['error']}", parent=self.root)
            elif job["kind"] == "upload":
                virustotal.open_url(job["result"].url)
                self.status.set(f"Uploaded {name} to VirusTotal; its analysis page is open in your browser.")
            else:
                virustotal.open_url(virustotal.report_url(job["result"]))
                self.status.set(f"Opened the VirusTotal page of {name}.")

    def lookup_virustotal(self) -> None:
        """Open the selected file's VirusTotal page. Only its hash leaves this computer."""
        from tkinter import messagebox

        path, digest = self._selected_path(), self._selected_sha256()
        if digest:
            virustotal.open_url(virustotal.report_url(digest))
            self.status.set(f"Opened the VirusTotal page of {sanitize.clean(os.path.basename(path), 120)}.")
            return
        if not path or not os.path.isfile(path):
            messagebox.showinfo("VirusTotal", "Select a file that is still on disk first.", parent=self.root)
            return
        self.status.set("Working out the file's fingerprint...")
        self._run_job("lookup", path, lambda: virustotal.sha256_of(path))

    def upload_virustotal(self) -> None:
        """Send the selected file to VirusTotal, after the user agrees, and show its analysis."""
        from tkinter import messagebox

        path = self._selected_path()
        if not path or not os.path.isfile(path):
            messagebox.showinfo("Upload to VirusTotal", "Select a file that is still on disk first.", parent=self.root)
            return
        shown = sanitize.clean(path, 300)
        if not messagebox.askyesno(
            "Upload to VirusTotal",
            f"Send this file to VirusTotal for scanning?\n\n{shown}\n\n"
            "The whole file is uploaded. VirusTotal shares uploaded files with security companies and others "
            "can find them, so never upload personal or confidential documents.\n\n"
            "To check a file without uploading it, use Look up on VirusTotal instead.",
            icon="warning", parent=self.root,
        ):
            return
        key = virustotal.api_key(self.ctl.config)
        if not key:
            virustotal.open_url(virustotal.upload_page_url())
            virustotal.reveal(path)
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            messagebox.showinfo(
                "Upload to VirusTotal",
                "VirusTotal's upload page is open in your browser and the file is selected in a folder window. "
                "Drag the file onto the page (its path is also on the clipboard).\n\n"
                "For one-click uploads, add a free VirusTotal API key under Settings.",
                parent=self.root,
            )
            return
        self.status.set(f"Uploading {sanitize.clean(os.path.basename(path), 120)} to VirusTotal...")
        self._run_job("upload", path, lambda: virustotal.upload(path, key))

    def about(self) -> None:
        from tkinter import messagebox

        messagebox.showinfo("About FileSpy", (
            f"FileSpy {__version__}\n\n"
            "Watches for dropped files, new autostart entries, security-setting changes and suspicious programs, "
            "and tells you about them.\n\n"
            "It observes and alerts. It is not an antivirus and does not replace one. Run samples you do not trust "
            "only in a disposable virtual machine.\n\n"
            f"Data folder: {self.ctl.data_dir}"), parent=self.root)

    def elevate(self) -> None:
        if relaunch_as_admin(["--data-dir", str(self.ctl.data_dir), "--config", str(self.ctl.config_file)]):
            self.close()

    def close(self) -> None:
        """Stop watching (which can take a moment), then close the window."""
        if self.ctl.state == "watching":
            self.ctl.stop()
        if self.ctl.state == "stopped":
            self.dispose()
        else:
            self._closing = True
            self._update_status()

    def dispose(self) -> None:
        """Destroy the window, freeing its Tk variables first while Tk is still running on this thread."""
        for name in ("status", "counts", "level", "find"):
            setattr(self, name, None)
        try:
            self.root.destroy()
        except self.tk.TclError:
            pass


def _selftest(result_file: str | None) -> int:
    """Run the headless self-test; used to check a built executable, which has no console."""
    from filespy.cli import main as cli_main

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli_main(["selftest", "--quiet"])
    if result_file:
        Path(result_file).write_text(buffer.getvalue(), encoding="utf-8")
    elif sys.stdout is not None:
        print(buffer.getvalue())
    return code


def needs_elevation(args: argparse.Namespace, platform: str = sys.platform, admin: bool | None = None) -> bool:
    """Windows only: whether to ask for administrator rights before opening the window."""
    if platform != "win32" or args.no_elevate or args.elevated or args.selftest or args.smoke_gui:
        return False
    if admin is None:
        from filespy.app import is_admin

        admin = is_admin()
    return not admin


def forwarded_arguments(args: argparse.Namespace) -> list[str]:
    """The window's options, handed to an elevated copy of it."""
    out = []
    if args.data_dir:
        out += ["--data-dir", args.data_dir]
    if args.config:
        out += ["--config", args.config]
    if args.start:
        out.append("--start")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="filespy-gui", description="FileSpy window")
    parser.add_argument("--data-dir", help="folder for settings, the event database, logs and quarantine")
    parser.add_argument("--config", help="settings file to use")
    parser.add_argument("--start", action="store_true", help="start watching as soon as the window opens")
    parser.add_argument("--selftest", action="store_true", help="run the self-test without a window and exit")
    parser.add_argument("--result-file", help="with --selftest: write the output to this file")
    parser.add_argument("--smoke-gui", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-elevate", action="store_true", help="do not ask for administrator rights on Windows")
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"FileSpy {__version__}")
    args = parser.parse_args(argv)
    if sys.stderr is None:  # a windowed executable has no console: keep errors in a file instead
        try:
            folder = ensure_private_dir(Path(args.data_dir) if args.data_dir else default_data_dir()) / "logs"
            folder.mkdir(parents=True, exist_ok=True)
            sys.stderr = open(folder / "gui-errors.log", "a", encoding="utf-8")  # noqa: SIM115
        except OSError:
            pass
    if args.selftest:
        return _selftest(args.result_file)
    if needs_elevation(args) and relaunch_as_admin(forwarded_arguments(args)):
        return 0  # the elevated copy takes over; if the user says no, carry on with less visibility
    try:
        import tkinter as tk
    except ImportError:
        print("filespy: Tkinter is not installed, so the window cannot open. Use the 'filespy' command instead.", file=sys.stderr)
        return 2
    controller = Controller(args.data_dir, args.config)
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"filespy: cannot open a window: {exc}", file=sys.stderr)
        return 2
    window = MainWindow(root, controller, autostart=args.start)
    if args.smoke_gui:
        root.after(2500, window.close)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
