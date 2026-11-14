"""File-drop monitor: tells you when a new file lands in a place malware likes to use.

Events come from watchdog (real time) or, without it, from a polling scanner. A new
file is examined once it has stopped changing, so half-written downloads are not
reported early, and it is remembered so that the process and autorun monitors can
recognise it later.
"""

from __future__ import annotations

import logging
import os
import queue
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from filespy import fileinfo, sanitize
from filespy.analyzer import FileReport
from filespy.events import Indicator, Severity
from filespy.monitors.base import Monitor
from filespy.paths import basename, default_watch_roots, drop_nested, is_excluded, is_within

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - exercised only without the dependency
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment]

log = logging.getLogger("filespy")

KIND_LABELS = {
    "pe": "program", "elf": "program", "macho": "program", "script": "script", "lnk": "shortcut",
    "ole": "installer or Office file", "html": "web page or HTML application", "zip": "archive",
    "rar": "archive", "7z": "archive", "cab": "archive", "pdf": "PDF", "javaclass": "Java class",
}
MAX_PENDING = 20000
MAX_QUEUE = 100000
MAX_DIR_WALK = 5000
MAX_READ_RETRIES = 4
RECHECK_COOLDOWN = 2.0  # seconds before an unchanged, already examined file is looked at again
RELOOK_WINDOW = 120.0  # how long after its creation a so-far harmless file is re-examined when it changes


def kind_label(report: FileReport) -> str:
    if report.ext in fileinfo.CONTAINER_EXTS:
        return "archive or disk image"
    return KIND_LABELS.get(report.kind, "file")


def _signature(path: str) -> tuple[int, int] | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return info.st_size, info.st_mtime_ns


@dataclass
class _Pending:
    action: str  # created | renamed | modified
    first_seen: float
    checked: float  # when the size and time of the file were last looked at
    renamed_from: str = ""
    signature: tuple[int, int] | None = None
    closed: bool = False
    not_before: float = 0.0
    jitter: int = 0  # consecutive looks where the time changed but the size did not


class PollingScanner:
    """Finds new, changed and deleted files by walking the watched folders. Never follows links."""

    def __init__(self, roots: list[str], recursive: bool, excluded: Callable[[str], bool], max_entries: int = 300000) -> None:
        self.roots = roots
        self.recursive = recursive
        self.excluded = excluded
        self.max_entries = max_entries
        self.index: dict[str, tuple[int, int]] = {}
        self.primed = False
        self.truncated = False

    def scan(self) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        seen: set[str] = set()
        count = 0
        complete = True
        stack = [(root, 0) for root in self.roots]
        while stack and complete:
            folder, depth = stack.pop()
            try:
                iterator = os.scandir(folder)
            except OSError:
                continue
            with iterator:
                for entry in iterator:
                    count += 1
                    if count > self.max_entries:
                        complete = False
                        break
                    path = entry.path
                    try:
                        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if self.recursive and depth < 40 and not self.excluded(path):
                                stack.append((path, depth + 1))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if self.excluded(path):
                        continue
                    signature = (info.st_size, info.st_mtime_ns)
                    seen.add(path)
                    previous = self.index.get(path)
                    if previous is None:
                        self.index[path] = signature
                        if self.primed:
                            events.append(("created", path))
                    elif previous != signature:
                        self.index[path] = signature
                        events.append(("modified", path))
        if complete:
            for path in [p for p in self.index if p not in seen]:
                del self.index[path]
                events.append(("deleted", path))
        self.truncated = not complete
        self.primed = True
        return events


class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    """Runs on the watchdog thread: only hands events over, never does work."""

    def __init__(self, push: Callable[[str, str, str], None]) -> None:
        self._push = push

    def on_created(self, event) -> None:  # noqa: ANN001
        self._push("dir" if event.is_directory else "created", os.fsdecode(event.src_path), "")

    def on_modified(self, event) -> None:  # noqa: ANN001
        if not event.is_directory:
            self._push("modified", os.fsdecode(event.src_path), "")

    def on_closed(self, event) -> None:  # noqa: ANN001
        if not event.is_directory:
            self._push("closed", os.fsdecode(event.src_path), "")

    def on_deleted(self, event) -> None:  # noqa: ANN001
        if not event.is_directory:
            self._push("deleted", os.fsdecode(event.src_path), "")

    def on_moved(self, event) -> None:  # noqa: ANN001
        if event.is_directory:
            self._push("dir", os.fsdecode(event.dest_path), "")
        else:
            self._push("moved", os.fsdecode(event.src_path), os.fsdecode(event.dest_path))


class FileMonitor(Monitor):
    name = "files"
    interval = 0.2

    # -- setup ----------------------------------------------------------------
    def resolve_roots(self) -> list[str]:
        cfg = self.ctx.config.files
        candidates = list(cfg.paths)
        if cfg.use_default_paths:
            candidates += default_watch_roots(self.ctx.platform)
        existing = [os.path.abspath(os.path.expanduser(p)) for p in candidates]
        existing = [p for p in existing if os.path.isdir(p) and not is_within(p, str(self.ctx.data_dir))]
        return drop_nested(existing)

    def setup(self) -> None:
        cfg = self.ctx.config.files
        self.roots = self.resolve_roots()
        self._data_dir = str(self.ctx.data_dir)
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=MAX_QUEUE)
        self._pending: dict[str, _Pending] = {}
        self._inflight: set[str] = set()
        self._recent: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._checked: dict[str, float] = {}
        self._retries: dict[str, int] = {}
        self._reported: dict[str, str] = {}  # path -> SHA-256 of the content last reported
        self._born: dict[str, float] = {}  # path -> when it was first examined
        self._relooks: dict[str, int] = {}  # path -> fruitless re-examinations so far (drives a back-off)
        self._truncation_reported = False
        self.stats = {"events": 0, "examined": 0, "reported": 0}
        self._burst: deque[tuple[float, str, str]] = deque()
        self._burst_quiet_until = 0.0
        self._lost = 0
        self._lost_reported = False
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="filespy-scan")
        self._observer = None
        self._scanner: PollingScanner | None = None
        self._next_scan = 0.0
        if not self.roots:
            raise RuntimeError("none of the folders to watch exist")
        if cfg.backend == "watchdog" and Observer is None:
            raise RuntimeError("watchdog is not installed (pip install watchdog)")
        polled = list(self.roots)
        if cfg.backend != "polling" and Observer is not None:
            polled = self._start_watchdog(cfg.recursive)
        if polled:
            self._scanner = PollingScanner(polled, cfg.recursive, self._excluded)
            self._scanner.scan()
            self._warn_if_truncated()
            self._next_scan = time.monotonic() + cfg.poll_interval
        mode = "real-time" if not polled else ("polling" if len(polled) == len(self.roots) else "real-time and polling")
        self.system("info", f"Watching {len(self.roots)} folder(s) for new files ({mode})")

    def _start_watchdog(self, recursive: bool) -> list[str]:
        """Watch every root we can in real time; return the roots that must be polled instead."""
        handler = _Handler(self._push)
        failed: list[str] = []
        if os.name == "nt":
            # Do not ask Windows for last-access notifications: merely looking at a file changes
            # its access time, so every check of ours would come back as another change event.
            try:
                from watchdog.observers import winapi

                winapi.WATCHDOG_FILE_NOTIFY_FLAGS &= ~0x20  # FILE_NOTIFY_CHANGE_LAST_ACCESS
            except Exception:  # noqa: BLE001 - internal detail of watchdog; the settle logic copes without it
                log.debug("could not adjust watchdog notify flags", exc_info=True)
        try:
            observer = Observer()
            observer.start()
        except Exception as exc:  # noqa: BLE001 - e.g. inotify instance limit
            log.warning("real-time file watching unavailable: %s", exc)
            return list(self.roots)
        for root in self.roots:
            try:
                observer.schedule(handler, root, recursive=recursive)
            except Exception as exc:  # noqa: BLE001 - missing folder, watch limit, access denied
                log.warning("cannot watch %s in real time (%s); polling it instead", root, exc)
                failed.append(root)
        self._observer = observer
        return failed

    def teardown(self) -> None:
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(3)
            except Exception:  # noqa: BLE001
                log.debug("observer shutdown failed", exc_info=True)
        # Do not start queued examinations, and give running ones a bounded time to finish.
        self._pool.shutdown(wait=False, cancel_futures=True)
        deadline = time.monotonic() + 5
        while self._inflight and time.monotonic() < deadline:
            time.sleep(0.05)
        waiting = len(self._pending) + len(self._inflight)
        self.system("info", f"File monitor: {self.stats['events']} change events, {self.stats['examined']} files examined, "
                            f"{self.stats['reported']} reported, {waiting} still waiting, {self._lost} skipped")

    def _warn_if_truncated(self) -> None:
        if self._scanner is not None and self._scanner.truncated and not self._truncation_reported:
            self._truncation_reported = True
            self.system("warning", f"The watched folders hold more than {self._scanner.max_entries:,} files, so only part "
                                   "of them is being watched. Watch fewer folders, or install watchdog for real-time watching.",
                        Severity.LOW)

    def _forget(self, path: str) -> None:
        """Drop everything remembered about a path whose file is gone or has moved away."""
        self.ctx.state.forget_drop(path)
        for table in (self._recent, self._checked, self._reported, self._born, self._relooks, self._retries):
            table.pop(path, None)

    # -- intake ---------------------------------------------------------------
    def _push(self, kind: str, path: str, dest: str) -> None:
        """Called on the watchdog thread for every file-system event."""
        fresh = path if kind == "created" else dest if kind == "moved" else ""
        if fresh and not self._excluded(fresh):
            # Remember it at once: a dropper often runs its payload within milliseconds.
            self.ctx.state.note_drop(fresh)
        try:
            self._queue.put_nowait((kind, path, dest))
        except queue.Full:
            self._lost += 1

    def _excluded(self, path: str) -> bool:
        return is_within(path, self._data_dir) or is_excluded(path, self.ctx.config.files.exclude)

    def poll(self) -> None:
        now = time.monotonic()
        for _ in range(5000):
            try:
                kind, path, dest = self._queue.get_nowait()
            except queue.Empty:
                break
            self._handle(kind, path, dest, now)
        if self._scanner is not None and now >= self._next_scan:
            started = time.monotonic()
            for kind, path in self._scanner.scan():
                self._handle(kind, path, "", now)
            self._warn_if_truncated()
            spent = time.monotonic() - started
            self._next_scan = time.monotonic() + max(self.ctx.config.files.poll_interval, 3 * spent)
        self._settle(now)
        self._check_burst(now)
        if self._lost and not self._lost_reported:
            self._lost_reported = True
            self.system("warning", "File events arrived faster than they could be processed; some were skipped")

    def _handle(self, kind: str, path: str, dest: str, now: float) -> None:
        self.stats["events"] += 1
        if kind == "moved":
            self._pending.pop(path, None)
            self._forget(path)  # nothing lives at the old name any more
            if dest and not self._excluded(dest):
                if fileinfo.extension(path) != fileinfo.extension(dest):
                    self._burst.append((now, dest, fileinfo.extension(dest)))
                self._add_pending(dest, "renamed", now, path)
            return
        if self._excluded(path):
            return
        if kind == "created":
            self._add_pending(path, "created", now)
        elif kind.startswith("retry:"):
            # The file could not be read a moment ago (still locked by its writer or by a scanner).
            self._recent.pop(path, None)
            self._add_pending(path, kind[6:], now, dest, not_before=now + 0.5 * self._retries.get(path, 1))
        elif kind == "dir":
            self._walk_new_dir(path, now)
        elif kind == "closed":
            pending = self._pending.get(path)
            if pending is not None:
                pending.closed = True
        elif kind == "modified":
            if path in self._pending:
                return  # already waiting; the settle check looks at the file itself
            ext = fileinfo.extension(path)
            if ext in fileinfo.DECOY_EXTS:
                self._burst.append((now, path, ext))
            # A file seen being created a moment ago may only now be getting its real content.
            young = path in self._recent and now - self._born.get(path, 0.0) < RELOOK_WINDOW
            if ext in fileinfo.RISKY_EXTS or young or self.ctx.state.lookup_drop(path) is not None:
                backoff = RECHECK_COOLDOWN * 2 ** min(self._relooks.get(path, 0), 5)
                self._add_pending(path, "modified", now, not_before=self._checked.get(path, 0.0) + backoff)
        elif kind == "deleted":
            self._on_deleted(path)

    def _add_pending(self, path: str, action: str, now: float, renamed_from: str = "", not_before: float = 0.0) -> None:
        existing = self._pending.get(path)
        if existing is not None:
            if action != "modified" and existing.action == "modified":
                # The file was replaced while a change to the old one was waiting: it is a new file now.
                existing.action, existing.renamed_from, existing.not_before = action, renamed_from, 0.0
                if self.ctx.state.lookup_drop(path) is None:
                    self.ctx.state.note_drop(path)
            return
        if len(self._pending) >= MAX_PENDING:
            self._lost += 1
            if action != "modified":
                self.ctx.state.forget_drop(path)  # it will never be examined, so do not keep a half-record
            return
        self._pending[path] = _Pending(action, now, now, renamed_from, _signature(path), not_before=not_before)
        if action != "modified" and self.ctx.state.lookup_drop(path) is None:
            self.ctx.state.note_drop(path)

    def _walk_new_dir(self, folder: str, now: float) -> None:
        """A whole folder appeared (moved or extracted in): pick up the files inside it."""
        if not self.ctx.config.files.recursive:
            return
        count = 0
        stack = [folder]
        while stack and count < MAX_DIR_WALK:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        count += 1
                        if count >= MAX_DIR_WALK:
                            break
                        if entry.is_symlink() or self._excluded(entry.path):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False) and entry.path not in self._recent:
                            self._add_pending(entry.path, "created", now)
            except OSError:
                continue

    def _on_deleted(self, path: str) -> None:
        pending = self._pending.pop(path, None)
        for table in (self._recent, self._checked, self._retries, self._reported, self._born, self._relooks):
            table.pop(path, None)
        name = sanitize.clean(basename(path), 120)
        if pending is not None and pending.action != "modified":
            self.ctx.state.forget_drop(path)
            if fileinfo.extension(path) in fileinfo.RISKY_EXTS:
                self.emit("file", "deleted", f"A new file vanished before it could be examined: {name}", path,
                          [Indicator("file.vanished", 20, "A runnable file was created and deleted again within seconds", "T1070.004")],
                          {"path": path})
            return
        record = self.ctx.state.lookup_drop(path)
        if record is not None and record.event_id:
            self.emit("file", "deleted", f"A dropped file was deleted: {name}", path,
                      details={"path": path, "sha256": record.sha256, "drop_event": record.event_id})

    # -- examination ----------------------------------------------------------
    def _settle(self, now: float) -> None:
        """Examine files whose size and modification time have stopped changing.

        Stability is judged by looking at the file, not by the absence of change events:
        on some systems our own look at a file produces another event for it.
        """
        cfg = self.ctx.config.files
        for path, pending in list(self._pending.items()):
            if path in self._inflight or now < pending.not_before:
                continue
            forced = pending.closed or now - pending.first_seen >= cfg.max_settle_seconds
            if not forced and now - pending.checked < cfg.settle_seconds:
                continue
            signature = _signature(path)
            if signature is None:
                del self._pending[path]
                self._on_vanished(path, pending)
                continue
            if not forced and signature != pending.signature:
                same_size = pending.signature is not None and signature[0] == pending.signature[0]
                pending.jitter = pending.jitter + 1 if same_size else 0
                pending.signature = signature
                pending.checked = now
                if pending.jitter < 2:
                    continue  # still changing: look again after another quiet period
                # The size is steady and only the timestamp keeps moving (seen on some
                # Windows and Python combinations): the file is complete.
            del self._pending[path]
            if self._recent.get(path) == signature:
                self._checked[path] = now  # unchanged since it was examined
                self._relooks[path] = self._relooks.get(path, 0) + 1
                continue
            self._remember(path, signature)
            self._inflight.add(path)
            future = self._pool.submit(self._examine, path, pending)
            future.add_done_callback(lambda _f, p=path: self._inflight.discard(p))

    def _remember(self, path: str, signature: tuple[int, int]) -> None:
        self._recent[path] = signature
        self._recent.move_to_end(path)
        self._born.setdefault(path, time.monotonic())
        while len(self._recent) > 20000:
            old, _ = self._recent.popitem(last=False)
            for table in (self._checked, self._reported, self._born, self._relooks):
                table.pop(old, None)

    def _on_vanished(self, path: str, pending: _Pending) -> None:
        if pending.action == "modified":
            return
        self.ctx.state.forget_drop(path)
        if fileinfo.extension(path) in fileinfo.RISKY_EXTS:
            name = sanitize.clean(basename(path), 120)
            self.emit("file", "deleted", f"A new file vanished before it could be examined: {name}", path,
                      [Indicator("file.vanished", 20, "A runnable file was created and deleted again within seconds", "T1070.004")],
                      {"path": path})

    def _examine(self, path: str, pending: _Pending) -> None:
        """Runs on a worker thread."""
        if self.stopping:
            return
        try:
            first_report = path not in self._reported
            if pending.action == "modified" and first_report and self._head_is_boring(path):
                self._relooks[path] = self._relooks.get(path, 0) + 1
                return  # still nothing runnable in it
            report = self.ctx.analyzer.analyze(path)
            self.stats["examined"] += 1
            if not report.exists:
                self._on_vanished(path, pending)
                return
            if pending.action == "modified" and report.sha256 and self._reported.get(path) == report.sha256:
                self._relooks[path] = self._relooks.get(path, 0) + 1
                return  # only its metadata changed; the content is what was already reported
            if report.error:
                # It exists but cannot be read right now: still locked by whatever wrote it, or by a scanner.
                attempt = self._retries.get(path, 0) + 1
                if attempt <= MAX_READ_RETRIES:
                    self._retries[path] = attempt
                    self._push("retry:" + pending.action, path, pending.renamed_from)
                    return
                self._retries.pop(path, None)
                if report.ext in fileinfo.RISKY_EXTS:
                    name = sanitize.clean(basename(path), 120)
                    self.emit("file", pending.action, f"A new runnable file could not be examined: {name}", path,
                              [Indicator("file.unreadable", 20, "The file is locked or access to it was denied", "T1564")],
                              {"path": path, "error": report.error})
                return
            self._retries.pop(path, None)
            if report.kind in ("link", "special"):
                self.ctx.state.forget_drop(path)
                return
            if not (report.interesting or report.indicators or self.ctx.config.files.report_all):
                if pending.action != "modified":
                    self.ctx.state.forget_drop(path)
                return
            name = sanitize.clean(basename(path), 120)
            label = kind_label(report)
            action = pending.action
            if action == "modified" and first_report:
                action = "created"  # it was created harmless a moment ago and only now received this content
            if action == "modified":
                title = f"A {label} was modified: {name}"
            elif action == "renamed":
                title = f"New {label} (renamed into place): {name}"
            else:
                title = f"New {label} dropped: {name}"
            details = report.to_details()
            if pending.renamed_from:
                details["renamed_from"] = pending.renamed_from
            event = self.emit("file", action, title, path, report.indicators, details)
            self.stats["reported"] += 1
            self._relooks.pop(path, None)
            if report.sha256:
                self._reported[path] = report.sha256
            if report.interesting:
                self.ctx.state.note_drop(path, report.sha256, event.id, event.score)
            elif pending.action != "modified":
                self.ctx.state.forget_drop(path)
        except Exception:  # noqa: BLE001 - never let one file stop the monitor
            log.exception("could not examine %r", path)

    @staticmethod
    def _head_is_boring(path: str) -> bool:
        """Cheap look at the first bytes: True if the file is still empty or shapeless data."""
        try:
            with fileinfo.open_regular(path) as handle:
                head = handle.read(4096)
        except OSError:
            return False
        kind = fileinfo.detect_kind(head, basename(path))
        return kind in ("empty", "data") and fileinfo.extension(path) not in fileinfo.RISKY_EXTS

    def idle(self) -> bool:
        """True when nothing is queued, waiting to settle or being examined (used by tests)."""
        return self._queue.empty() and not self._pending and not self._inflight

    # -- mass change detection -------------------------------------------------
    def _check_burst(self, now: float) -> None:
        cfg = self.ctx.config.files
        while self._burst and now - self._burst[0][0] > cfg.burst_window:
            self._burst.popleft()
        latest = {path: ext for _when, path, ext in self._burst}  # one entry per file, however often it changed
        if len(latest) < cfg.burst_threshold or now < self._burst_quiet_until:
            return
        self._burst_quiet_until = now + 60
        paths = list(latest)
        extensions = Counter(latest.values())
        top_ext, top_count = extensions.most_common(1)[0]
        indicators = [Indicator("file.mass_change", 60, f"{len(paths)} files were renamed or rewritten within {int(cfg.burst_window)} seconds", "T1486")]
        known = fileinfo.DECOY_EXTS | fileinfo.RISKY_EXTS | fileinfo.CONTAINER_EXTS | {"tmp", "bak", "part", "crdownload"}
        if top_ext and top_ext not in known and top_count >= len(paths) * 0.6:
            indicators.append(Indicator("file.mass_new_extension", 40, f"Most of them now end in the unusual extension .{sanitize.clean(top_ext, 20)}", "T1486"))
        self.emit("file", "burst", "Many files are being renamed or rewritten at once (possible ransomware)",
                  os.path.dirname(paths[-1]), indicators,
                  {"count": len(paths), "examples": paths[-5:], "top_extension": top_ext})
        self._burst.clear()
