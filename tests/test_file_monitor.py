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
