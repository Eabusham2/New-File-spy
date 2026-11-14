import os
import sys
import time

import pytest

from filespy.events import Severity
from filespy.monitors.files import FileMonitor, PollingScanner
from filespy.testing import make_elf, make_pe, test_threat_bytes, wait_for


@pytest.fixture(params=["auto", "polling"])
def running(request, make_ctx, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    ctx = make_ctx(files__backend=request.param)
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    assert monitor.ready.wait(10) and not monitor.failed
    yield ctx, monitor, watched
    monitor.stop()
    monitor.join()


def file_events(ctx, action=None):
    return ctx.bus.find("file", action)


def test_dropped_program_is_reported_and_remembered(running):
    ctx, _monitor, watched = running
    target = watched / "payload.exe"
    target.write_bytes(make_pe())
    events = wait_for(lambda: file_events(ctx, "created"))
    assert events, "no event for a dropped program"
    event = events[0]
    assert event.details["kind"] == "pe" and event.details["sha256"] and "payload.exe" in event.title
    record = wait_for(lambda: (r := ctx.state.lookup_drop(str(target))) and r.event_id and r)
    assert record and record.sha256 == event.details["sha256"]


def test_eicar_drop_is_critical(running):
    ctx, _monitor, watched = running
    (watched / "test.com").write_bytes(test_threat_bytes())
    events = wait_for(lambda: [e for e in file_events(ctx) if e.severity is Severity.CRITICAL])
    assert events and any(i.id == "file.rule.filespy.selftest" for i in events[0].indicators)


def test_ordinary_files_stay_quiet_unless_asked(running):
    ctx, monitor, watched = running
    (watched / "notes.txt").write_text("hello")
    (watched / "trigger.exe").write_bytes(make_pe())
    assert wait_for(lambda: file_events(ctx, "created"))
    wait_for(monitor.idle)
    assert all("notes.txt" not in e.subject for e in file_events(ctx))
    assert ctx.state.lookup_drop(str(watched / "notes.txt")) is None


def test_report_all_records_ordinary_files(make_ctx, tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx(files__report_all=True)
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        (watched / "notes.txt").write_text("hello")
        events = wait_for(lambda: file_events(ctx, "created"))
        assert events and events[0].severity is Severity.INFO
    finally:
        monitor.stop()
        monitor.join()


def test_rename_into_runnable_name(running):
    ctx, monitor, watched = running
    temp = watched / "download.part"
    temp.write_bytes(make_elf())
    wait_for(lambda: ctx.bus.find("file"))
    wait_for(monitor.idle)
    ctx.bus.events.clear()
    final = watched / "tool.bin"
    os.replace(temp, final)
    events = wait_for(lambda: [e for e in file_events(ctx) if "tool.bin" in e.subject])
    assert events and events[0].details["kind"] == "elf"
    assert wait_for(lambda: ctx.state.lookup_drop(str(final)))


def test_file_in_new_subfolder_is_seen(running):
    ctx, _monitor, watched = running
    sub = watched / "a" / "b"
    sub.mkdir(parents=True)
    (sub / "deep.exe").write_bytes(make_pe())
    assert wait_for(lambda: [e for e in file_events(ctx) if "deep.exe" in e.subject])


def test_excluded_and_data_dir_paths_are_ignored(make_ctx, tmp_path):
    watched = tmp_path / "w"
    (watched / "node_modules" / "x").mkdir(parents=True)
    ctx = make_ctx()
    ctx.config.files.paths = [str(watched), str(ctx.data_dir)]
    monitor = FileMonitor(ctx)
    assert str(ctx.data_dir) not in monitor.resolve_roots()
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        (watched / "node_modules" / "x" / "skip.exe").write_bytes(make_pe())
        (watched / "seen.exe").write_bytes(make_pe())
        assert wait_for(lambda: [e for e in file_events(ctx) if "seen.exe" in e.subject])
        wait_for(monitor.idle)
        assert not [e for e in file_events(ctx) if "skip.exe" in e.subject]
    finally:
        monitor.stop()
        monitor.join()


def test_short_lived_runnable_file_is_noted(make_ctx, tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx(files__settle_seconds=1.0, files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        target = watched / "flash.exe"
        target.write_bytes(make_pe())
        assert wait_for(lambda: str(target) in monitor._pending, 5)
        target.unlink()
        events = wait_for(lambda: ctx.bus.find("file", "deleted"))
        assert events and any(i.id == "file.vanished" for i in events[0].indicators)
    finally:
        monitor.stop()
        monitor.join()


def test_mass_rename_burst(make_ctx, tmp_path):
    watched = tmp_path / "docs"
    watched.mkdir()
    for n in range(12):
        (watched / f"report{n}.docx").write_text("x")
    ctx = make_ctx(files__burst_threshold=10)
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        time.sleep(0.3)
        for n in range(12):
            os.replace(watched / f"report{n}.docx", watched / f"report{n}.docx.lockd")
        events = wait_for(lambda: ctx.bus.find("file", "burst"), 15)
        if not events and monitor._observer is None:
            pytest.skip("rename bursts need real-time events")
        assert events and events[0].severity >= Severity.MEDIUM
        assert any(i.id == "file.mass_new_extension" for i in events[0].indicators)
    finally:
        monitor.stop()
        monitor.join()


def test_polling_scanner_reports_changes_and_never_follows_links(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.exe").write_bytes(b"x")
    (root / "old.txt").write_text("1")
    scanner = PollingScanner([str(root)], True, lambda p: False)
    assert scanner.scan() == []
    (root / "new.exe").write_bytes(b"MZ")
    if sys.platform != "win32":
        os.symlink(outside, root / "link")
    assert scanner.scan() == [("created", str(root / "new.exe"))]
    time.sleep(0.01)
    (root / "new.exe").write_bytes(b"MZ-changed")
    assert scanner.scan() == [("modified", str(root / "new.exe"))]
    (root / "old.txt").unlink()
    assert scanner.scan() == [("deleted", str(root / "old.txt"))]


def test_monitor_fails_cleanly_without_folders(make_ctx):
    ctx = make_ctx()
    monitor = FileMonitor(ctx)
    monitor.start()
    assert monitor.ready.wait(5) and monitor.failed
    assert ctx.bus.find("system", "error")


def test_noisy_change_events_do_not_delay_examination(make_ctx, tmp_path):
    """Windows can report a change every time a file is merely looked at; that must not postpone the report."""
    import threading

    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx(files__settle_seconds=0.2, files__max_settle_seconds=60.0)
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    target = watched / "noisy.exe"
    stop = threading.Event()

    def noise():
        while not stop.wait(0.02):
            monitor._push("modified", str(target), "")

    thread = threading.Thread(target=noise, daemon=True)
    try:
        assert monitor.ready.wait(10)
        thread.start()
        target.write_bytes(make_pe())
        started = time.monotonic()
        assert wait_for(lambda: file_events(ctx, "created"), 10), "examination was postponed by change events"
        assert time.monotonic() - started < 8
        time.sleep(1.0)  # the noise continues: it must not cause repeat reports either
        assert len([e for e in file_events(ctx) if "noisy.exe" in e.subject]) == 1
    finally:
        stop.set()
        thread.join()
        monitor.stop()
        monitor.join()


def test_unreadable_file_is_retried_then_reported(make_ctx, tmp_path):
    from filespy.analyzer import FileReport

    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx()
    ctx.config.files.paths = [str(watched)]
    real = ctx.analyzer.analyze
    failures = {"left": 2}

    def flaky(path):
        if path.endswith("locked.exe") or failures["left"] > 0:
            failures["left"] -= 1
            return FileReport(path=path, ext="exe", error="cannot read: Permission denied")
        return real(path)

    ctx.analyzer.analyze = flaky
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        (watched / "slow.exe").write_bytes(make_pe())
        recovered = wait_for(lambda: [e for e in file_events(ctx) if "slow.exe" in e.subject], 20)
        assert recovered and recovered[0].details["kind"] == "pe", "a file that became readable was not reported"
        (watched / "locked.exe").write_bytes(make_pe())
        blocked = wait_for(lambda: [e for e in file_events(ctx) if "locked.exe" in e.subject], 30)
        assert blocked and any(i.id == "file.unreadable" for i in blocked[0].indicators)
        assert ctx.state.lookup_drop(str(watched / "locked.exe")) is not None  # still remembered for correlation
    finally:
        monitor.stop()
        monitor.join()


def test_timestamp_that_keeps_moving_does_not_block_the_report(make_ctx, tmp_path, monkeypatch):
    """If the reported modification time of a finished file will not hold still, it must still be examined."""
    import itertools

    from filespy.monitors import files as files_module

    watched = tmp_path / "w"
    watched.mkdir()
    counter = itertools.count()
    real = files_module._signature

    def restless(path):
        signature = real(path)
        return None if signature is None else (signature[0], signature[1] + next(counter))

    monkeypatch.setattr(files_module, "_signature", restless)
    ctx = make_ctx(files__settle_seconds=0.1, files__max_settle_seconds=60.0, files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        (watched / "restless.exe").write_bytes(make_pe())
        assert wait_for(lambda: file_events(ctx, "created"), 10), "a moving timestamp blocked the report"
        time.sleep(1.5)
        monitor._push("modified", str(watched / "restless.exe"), "")
        time.sleep(1.5)
        reports = [e for e in file_events(ctx) if "restless.exe" in e.subject]
        assert len(reports) == 1, "an unchanged file was reported again"
    finally:
        monitor.stop()
        monitor.join()
    summary = [e for e in ctx.bus.find("system", "info") if e.title.startswith("File monitor:")]
    assert summary and "1 reported" in summary[0].title


def test_replacing_a_file_that_was_waiting_as_modified_counts_as_a_new_file(make_ctx, tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx(files__settle_seconds=0.3, files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        target = watched / "swap.exe"
        monitor._push("modified", str(target), "")  # a change notice arrives before the creation notice
        time.sleep(0.25)
        target.write_bytes(make_pe())
        monitor._push("created", str(target), "")
        events = wait_for(lambda: [e for e in file_events(ctx) if "swap.exe" in e.subject], 10)
        assert events and events[0].action == "created"
    finally:
        monitor.stop()
        monitor.join()


def test_report_how_stable_file_times_are_on_this_platform(tmp_path):
    """Never fails: records, as a warning in the test summary, what repeated looks at one file return."""
    import warnings

    from filespy.monitors.files import _signature

    target = tmp_path / "probe.exe"
    target.write_bytes(make_pe())
    seen = []
    for _ in range(12):
        seen.append(_signature(str(target)))
        os.path.realpath(str(target))
        time.sleep(0.1)
    distinct = sorted(set(seen), key=seen.index)
    if len(distinct) > 1:
        warnings.warn(f"file signature changed without the file being written: {distinct[:6]}", stacklevel=1)


def test_program_written_into_a_file_that_started_empty_is_detected(make_ctx, tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    ctx = make_ctx(files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        target = watched / "payload"
        target.write_bytes(b"")
        assert wait_for(lambda: str(target) in monitor._recent, 10)  # examined while still empty
        wait_for(monitor.idle)
        assert not ctx.bus.find("file")
        target.write_bytes(make_elf())
        events = wait_for(lambda: [e for e in ctx.bus.find("file") if "payload" in e.subject], 15)
        assert events, "content written after the first look was never examined"
        assert events[0].action == "created" and events[0].details["kind"] == "elf"
        assert wait_for(lambda: (r := ctx.state.lookup_drop(str(target))) and r.event_id)
    finally:
        monitor.stop()
        monitor.join()


def test_rewriting_one_document_is_not_a_burst_but_many_documents_are(make_ctx, tmp_path):
    watched = tmp_path / "docs"
    watched.mkdir()
    ctx = make_ctx(files__burst_threshold=5, files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        for _ in range(60):
            monitor._push("modified", str(watched / "big.pdf"), "")
        time.sleep(0.8)
        assert not ctx.bus.find("file", "burst")
        for n in range(6):
            monitor._push("modified", str(watched / f"report{n}.docx"), "")
        assert wait_for(lambda: ctx.bus.find("file", "burst"), 10)
        assert ctx.bus.find("file", "burst")[0].details["count"] >= 6
    finally:
        monitor.stop()
        monitor.join()


def test_renamed_away_file_leaves_no_record_behind(running):
    ctx, monitor, watched = running
    if monitor._observer is None:
        pytest.skip("when polling, a rename is seen as a delete plus a create, and a deleted drop is kept on record")
    first = watched / "a.tmp"
    first.write_bytes(make_pe())
    assert wait_for(lambda: ctx.state.lookup_drop(str(first)), 10)
    wait_for(monitor.idle)
    os.replace(first, watched / "b.txt")
    assert wait_for(lambda: ctx.state.lookup_drop(str(first)) is None, 10), "a record for the old name lingered"


def test_partial_polling_scan_is_announced(make_ctx, tmp_path, monkeypatch):
    from filespy.monitors import files as files_module

    watched = tmp_path / "many"
    watched.mkdir()
    for n in range(12):
        (watched / f"f{n}.txt").write_text("x")
    real = files_module.PollingScanner
    monkeypatch.setattr(files_module, "PollingScanner", lambda roots, recursive, excluded: real(roots, recursive, excluded, max_entries=5))
    ctx = make_ctx(files__backend="polling")
    ctx.config.files.paths = [str(watched)]
    monitor = FileMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10)
        warnings = [e for e in ctx.bus.find("system", "warning") if "only part" in e.title]
        assert len(warnings) == 1
    finally:
        monitor.stop()
        monitor.join()


def fake_winapi(complete=True, with_reader=True):
    """Stand-in for watchdog.observers.winapi, which only imports on Windows."""
    import queue as queue_module
    import types

    module = types.ModuleType("watchdog.observers.winapi")

    class NativeEvent:
        def __init__(self, action, src_path, is_attrib=False):
            self.action, self.src_path, self.is_attrib = action, src_path, is_attrib

    module.WinAPINativeEvent = NativeEvent
    module._parse_event_buffer = lambda buf: [(1, name) for name in buf.decode().split(",")]
    if complete:
        module._parse_extended_event_buffer = lambda buf: [(3, name, True) for name in buf.decode().split(",")]
    module._drop_case_only_rename_deletions = lambda events: events

    if with_reader:
        class DirectoryChangeReader:
            def __init__(self):
                self._buf_queue = queue_module.Queue()

            def get_events(self, timeout):  # what watchdog 7.1 does
                events = []
                while True:
                    try:
                        buf, is_extended = self._buf_queue.get(timeout=timeout)
                    except queue_module.Empty:
                        break
                    if buf:
                        events.extend(module._parse_event_buffer(buf))
                return events

        module.DirectoryChangeReader = DirectoryChangeReader
    return module


def feed(reader, stop, interval=0.05):
    count = 0
    while not stop.wait(interval):
        count += 1
        reader._buf_queue.put((f"file{count}".encode(), False))


def test_windows_reader_hands_over_events_while_the_folder_stays_busy(monkeypatch):
    import sys
    import threading

    from filespy.monitors.files import fix_watchdog_windows_reader

    module = fake_winapi()
    monkeypatch.setitem(sys.modules, "watchdog.observers.winapi", module)
    original = module.DirectoryChangeReader.get_events

    # The problem: with changes arriving every 50 ms, watchdog 7.1 never returns from get_events.
    starved, stop = module.DirectoryChangeReader(), threading.Event()
    producer = threading.Thread(target=feed, args=(starved, stop), daemon=True)
    producer.start()
    result = []
    consumer = threading.Thread(target=lambda: result.append(original(starved, 0.5)), daemon=True)
    consumer.start()
    consumer.join(1.5)
    assert consumer.is_alive(), "the fake no longer reproduces watchdog 7.1's behaviour"
    stop.set()
    consumer.join(5)
    producer.join(5)

    # The fix: the same busy stream hands over events within a fraction of a second.
    assert fix_watchdog_windows_reader() is True
    assert module.DirectoryChangeReader.get_events._filespy_prompt
    assert fix_watchdog_windows_reader() is True  # applying it twice changes nothing
    reader, stop = module.DirectoryChangeReader(), threading.Event()
    producer = threading.Thread(target=feed, args=(reader, stop), daemon=True)
    producer.start()
    try:
        started = time.monotonic()
        events = reader.get_events(1.0)
        assert events and time.monotonic() - started < 0.5
    finally:
        stop.set()
        producer.join(5)

    quiet = module.DirectoryChangeReader()
    assert quiet.get_events(0.05) == []
    quiet._buf_queue.put((b"", False))  # the marker the reader thread sends when it starts
    quiet._buf_queue.put((b"a,b", False))
    quiet._buf_queue.put((b"c", True))
    found = [(e.action, e.src_path, e.is_attrib) for e in quiet.get_events(0.05)]
    assert found == [(1, "a", False), (1, "b", False), (3, "c", True)]


def test_windows_reader_fix_on_other_watchdog_versions(monkeypatch):
    import sys

    from filespy.monitors.files import fix_watchdog_windows_reader

    monkeypatch.setitem(sys.modules, "watchdog.observers.winapi", fake_winapi(with_reader=False))
    assert fix_watchdog_windows_reader() is True  # watchdog 6: nothing to fix
    monkeypatch.setitem(sys.modules, "watchdog.observers.winapi", fake_winapi(complete=False))
    assert fix_watchdog_windows_reader() is False  # unknown layout: do not rely on real-time watching
    monkeypatch.setitem(sys.modules, "watchdog.observers.winapi", None)  # the import fails (not Windows)
    assert fix_watchdog_windows_reader() is True


def test_continuous_activity_does_not_hide_a_new_drop(running):
    """A folder that never goes quiet (Temp, AppData) must still report a new program promptly."""
    import threading

    ctx, _monitor, watched = running
    busy = watched / "busy.tmp"
    stop = threading.Event()

    def churn():
        count = 0
        while not stop.wait(0.1):
            count += 1
            busy.write_text(str(count))

    churner = threading.Thread(target=churn, daemon=True)
    churner.start()
    try:
        time.sleep(1.5)
        (watched / "late.exe").write_bytes(make_pe())
        assert wait_for(lambda: [e for e in file_events(ctx) if "late.exe" in e.subject], 10), \
            "a drop in a busy folder was not reported"
    finally:
        stop.set()
        churner.join(5)
