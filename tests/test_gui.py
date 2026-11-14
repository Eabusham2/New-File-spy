import os
import time

import pytest

from filespy import gui
from filespy.events import Indicator, Severity, make_event
from filespy.testing import make_pe, test_threat_bytes, wait_for

HOSTILE = "evil\x1b[2J‮gpj.exe\nFAKE"


def sample(score=80, title="New program dropped: " + HOSTILE, category="file"):
    return make_event(category, "created", title, "/tmp/" + HOSTILE, [Indicator("x", score, "why " + HOSTILE, "T1105")],
                      {"path": "/tmp/x.exe", "sha256": "ab" * 32, "size": 12, "added_lines": ["curl x | sh"]})


def test_rows_and_details_are_safe_to_display():
    event = sample()
    row = gui.row_for(event)
    assert row[1] == "HIGH" and row[2] == "file"
    text = gui.details_for(event)
    for chunk in (*row, text):
        assert "\x1b" not in chunk and "‮" not in chunk
    assert "\nFAKE" not in text  # a file name cannot forge a line of its own
    assert "Why it was flagged" in text and "SHA-256: " + "ab" * 32 in text and "curl x | sh" in text and "T1105" in text


def test_event_log_filters_counts_and_is_bounded():
    log = gui.EventLog(limit=3)
    low, high = sample(25, "low thing"), sample(80, "high thing")
    notice = make_event("system", "warning", "A monitor could not start", min_severity=Severity.LOW)
    quiet = make_event("system", "info", "Watching 3 folders")
    for event in (low, high, notice, quiet):
        log.add(event)
    assert len(log.events) == 3 and log.counts["high"] == 1 and log.counts["low"] == 1
    assert [e.title for e in log.visible(Severity.HIGH)] == ["A monitor could not start", "high thing"]
    assert [e.title for e in log.visible(Severity.INFO)][0] == "Watching 3 folders"
    assert [e.title for e in log.visible(Severity.INFO, "HIGH")] == ["high thing"]
    assert "High 1" in log.summary() and "Critical 0" in log.summary()
    log.clear()
    assert not log.events and not log.counts
    assert "Nothing suspicious" in gui.audit_text([])
    assert "1 finding" in gui.audit_text([{"severity": "high", "area": "autorun", "title": HOSTILE, "subject": "x", "reasons": ["r"]}])


def make_controller(tmp_path, watched):
    controller = gui.Controller(tmp_path / "data")
    cfg = controller.config
    cfg.files.use_default_paths = False
    cfg.files.paths = [str(watched)]
    cfg.files.settle_seconds = 0.1
    cfg.alerts.desktop = False
    for name in ("processes", "network", "autoruns", "settings"):
        getattr(cfg, name).enabled = False
    controller.save_config()
    return controller


def test_controller_runs_a_session_without_any_window(tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    controller = make_controller(tmp_path, watched)
    assert controller.state == "stopped" and controller.start() and not controller.start()
    assert wait_for(lambda: controller.state == "watching", 60), controller.error
    assert controller.monitors == ["files"]
    (watched / "marker.bin").write_bytes(test_threat_bytes())

    def critical():
        controller.drain()
        return [e for e in controller.log.events if e.severity is Severity.CRITICAL]

    assert wait_for(critical, 30)
    report, count = controller.export("html", tmp_path / "out" / "report.html")
    assert count >= 1 and report.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert isinstance(controller.audit(), list)
    (watched / "tool.exe").write_bytes(make_pe())
    record = controller.quarantine(str(watched / "tool.exe"))
    assert record.original_removed and not (watched / "tool.exe").exists()
    assert controller.stop() and wait_for(lambda: controller.state == "stopped", 30)
    assert controller.app is None and not controller.stop()


def test_controller_reports_a_start_failure(tmp_path, monkeypatch):
    controller = make_controller(tmp_path, tmp_path)
    monkeypatch.setattr("filespy.app.App.start", lambda self, ready_timeout=90.0: (_ for _ in ()).throw(RuntimeError("no luck")))
    controller.start()
    assert wait_for(lambda: controller.state == "stopped" and controller.error, 30)
    assert "no luck" in controller.error


def test_selftest_mode_writes_its_result_to_a_file(tmp_path):
    result = tmp_path / "selftest.txt"
    assert gui.main(["--selftest", "--result-file", str(result)]) == 0
    assert "PASS" in result.read_text(encoding="utf-8")


def test_open_folder_never_opens_a_file(tmp_path):
    target = tmp_path / "run-me.exe"
    target.write_bytes(b"x")
    assert gui.open_folder(str(target)) is False
    assert gui.open_folder(str(tmp_path / "missing")) is False


@pytest.fixture
def window(tmp_path):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display available: {exc}")
    watched = tmp_path / "w"
    watched.mkdir()
    controller = make_controller(tmp_path, watched)
    main_window = gui.MainWindow(root, controller)
    yield main_window, controller, watched, root
    if controller.state == "watching":
        controller.stop()
    wait_for(lambda: controller.state == "stopped", 30)
    try:
        root.destroy()
    except tk.TclError:
        pass


def pump(root, condition, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        value = condition()
        if value:
            return value
        time.sleep(0.02)
    return condition()


def test_window_shows_alerts_filters_them_and_saves_settings(window):
    main_window, controller, watched, root = window
    assert main_window.toggle_button.cget("text") == "Start watching"
    main_window.toggle()
    assert pump(root, lambda: controller.state == "watching", 60), controller.error
    assert pump(root, lambda: main_window.toggle_button.cget("text") == "Stop watching", 10)
    assert "Watching: files" in main_window.status.get()

    (watched / "marker.bin").write_bytes(test_threat_bytes())
    (watched / "tool.exe").write_bytes(make_pe())
    assert pump(root, lambda: len(main_window.tree.get_children()) >= 2), "alerts did not reach the list"
    rows = {main_window.tree.item(item, "values")[1]: item for item in main_window.tree.get_children()}
    assert "CRITICAL" in rows
    main_window.tree.selection_set(rows["CRITICAL"])
    root.update()
    assert "Why it was flagged" in main_window.details.get("1.0", "end")
    assert "Critical 1" in main_window.counts.get()

    main_window.level.set("Critical only")
    main_window.refresh()
    assert [main_window.tree.item(i, "values")[1] for i in main_window.tree.get_children()] == ["CRITICAL"]
    main_window.level.set("Low and above")
    main_window.find.set("tool.exe")
    root.update()
    assert len(main_window.tree.get_children()) == 1

    dialog = main_window.settings()
    root.update()
    controller.config.alerts.sound = False
    dialog.save()
    root.update()
    assert os.path.exists(controller.config_file)

    main_window.toggle()
    assert pump(root, lambda: controller.state == "stopped", 30)
    assert pump(root, lambda: main_window.toggle_button.cget("text") == "Start watching", 10)
    main_window.clear()
    assert not main_window.tree.get_children()
