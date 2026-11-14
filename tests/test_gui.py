import hashlib
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
    main_window.dispose()


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


def file_event(path, action="created", severity_score=0, sha256="ab" * 32, kind="pe", size=1024):
    indicators = [Indicator("x", severity_score, "why")] if severity_score else []
    return make_event("file", action, f"New file: {os.path.basename(path)}", str(path), indicators,
                      {"path": str(path), "sha256": sha256, "kind": kind, "size": size})


def test_file_list_keeps_one_row_per_file_with_its_latest_state(tmp_path):
    files = gui.FileList(limit=3)
    a = tmp_path / "a.exe"
    assert files.note(file_event(a, severity_score=80)).status == "New"
    files.note(file_event(a, "modified", severity_score=25, sha256="cd" * 32))
    entry = files.note(file_event(a, "deleted", sha256=""))
    assert len(files.items) == 1 and entry.status == "Deleted" and entry.history == ["New", "Changed", "Deleted"]
    assert entry.severity is Severity.LOW and entry.sha256 == "cd" * 32  # deletion keeps the last examination
    quarantined = make_event("system", "response", "Quarantined", str(a), details={"path": str(a), "quarantine_id": "q"})
    assert files.note(quarantined).status == "Quarantined"
    for n in range(4):
        files.note(file_event(tmp_path / f"f{n}.txt", kind="text"))
    assert len(files.items) == 3 and [e.name for e in files.visible()] == ["f3.txt", "f2.txt", "f1.txt"]
    assert [e.name for e in files.visible("F2")] == ["f2.txt"]
    assert files.note(make_event("process", "started", "p")) is None
    row = files.get(str(tmp_path / "f3.txt")).row()
    assert row[1] == "New" and row[2] == "f3.txt" and row[3] == "Text" and row[6] == "Check / Upload"
    assert gui.human_size(512) == "512 bytes" and gui.human_size(5 * 1024 * 1024) == "5.0 MB" and gui.human_size(None) == ""
    hostile = gui.FileEntry(str(tmp_path / "x\u202egpj.exe"), "New", file_event(a), Severity.HIGH, 0.0)
    assert "\u202e" not in "".join(hostile.row())


def test_file_list_follows_a_renamed_file(tmp_path):
    files = gui.FileList()
    part, final = tmp_path / "payload.tmp", tmp_path / "payload.exe"
    files.note(file_event(part, kind="data"))
    renamed = file_event(final, "renamed")
    renamed.details["renamed_from"] = str(part)
    entry = files.note(renamed)
    assert list(files.items) == [gui.FileList.key(str(final))]  # no row is left for the old name
    assert entry.path == str(final) and entry.renamed_from == str(part) and entry.history == ["New", "Renamed"]
    files.note(file_event(part, kind="text"))  # a new file that takes the old name is a file of its own
    assert len(files.items) == 2 and files.get(str(part)).history == ["New"]


def test_lookups_use_the_file_as_it_is_now(tmp_path):
    target = tmp_path / "a.txt"
    target.write_bytes(b"rewritten")
    assert gui.current_sha256(str(target), "ab" * 32) == hashlib.sha256(b"rewritten").hexdigest()
    assert gui.current_sha256(str(tmp_path / "gone"), "ab" * 32) == "ab" * 32  # gone: the recorded hash
    with pytest.raises(OSError):
        gui.current_sha256(str(tmp_path / "gone"))


def test_the_elevated_window_starts_without_a_console(tmp_path):
    (tmp_path / "python.exe").write_bytes(b"")
    assert gui.windowed_python(str(tmp_path / "python.exe")) == str(tmp_path / "python.exe")  # no pythonw.exe there
    (tmp_path / "pythonw.exe").write_bytes(b"")
    assert gui.windowed_python(str(tmp_path / "python.exe")) == str(tmp_path / "pythonw.exe")
    assert gui.windowed_python(str(tmp_path / "FileSpy.exe")) == str(tmp_path / "FileSpy.exe")


def test_elevation_is_only_asked_for_on_windows_when_needed(tmp_path, monkeypatch):
    import argparse

    def args(**kw):
        base = {"no_elevate": False, "elevated": False, "selftest": False, "smoke_gui": False,
                "data_dir": None, "config": None, "start": False}
        base.update(kw)
        return argparse.Namespace(**base)

    assert gui.needs_elevation(args(), "win32", admin=False)
    assert not gui.needs_elevation(args(), "win32", admin=True)
    assert not gui.needs_elevation(args(), "linux", admin=False)
    for flag in ("no_elevate", "elevated", "selftest", "smoke_gui"):
        assert not gui.needs_elevation(args(**{flag: True}), "win32", admin=False)
    forwarded = gui.forwarded_arguments(args(data_dir="D", config="C", start=True))
    assert forwarded == ["--data-dir", os.path.abspath("D"), "--config", os.path.abspath("C"), "--start"]
    # The elevated copy gets a fresh environment, so the data folder is worked out here and passed on.
    monkeypatch.setenv("FILESPY_HOME", str(tmp_path / "home"))
    assert gui.forwarded_arguments(args()) == ["--data-dir", str(tmp_path / "home")]
    if os.name != "nt":
        assert gui.relaunch_as_admin(["--start"]) is False


def test_files_tab_lists_every_file_and_offers_virustotal(window, monkeypatch):
    from tkinter import messagebox

    main_window, controller, watched, root = window
    opened, revealed, said = [], [], []
    monkeypatch.setattr("filespy.virustotal.open_url", lambda url: opened.append(url) or True)
    monkeypatch.setattr("filespy.virustotal.reveal", lambda path: revealed.append(path) or True)
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: said.append("asked") or True)
    monkeypatch.setattr(messagebox, "showinfo", lambda *a, **k: said.append("info"))
    monkeypatch.setattr(messagebox, "showerror", lambda title, text, **k: said.append("error:" + text))
    monkeypatch.delenv("FILESPY_VT_KEY", raising=False)

    main_window.toggle()
    assert pump(root, lambda: controller.state == "watching", 60), controller.error
    (watched / "notes.txt").write_text("an ordinary file")
    (watched / "tool.exe").write_bytes(make_pe())
    assert pump(root, lambda: len(main_window.files_tree.get_children()) >= 2), "files did not reach the Files tab"
    names = {main_window.files_tree.item(i, "values")[2]: i for i in main_window.files_tree.get_children()}
    assert {"notes.txt", "tool.exe"} <= set(names)
    assert "files" in main_window.counts.get()

    main_window.notebook.select(1)
    main_window.files_tree.selection_set(names["tool.exe"])
    root.update()
    assert main_window.on_files_tab() and "Status: New" in main_window.details.get("1.0", "end")
    main_window.lookup_virustotal()  # hashes the file as it is now; only the hash leaves the computer
    assert pump(root, lambda: not main_window.jobs, 10)
    tool_hash = hashlib.sha256((watched / "tool.exe").read_bytes()).hexdigest()
    assert opened and opened[-1] == "https://www.virustotal.com/gui/file/" + tool_hash
    main_window.copy_path()
    assert root.clipboard_get().endswith("tool.exe")

    main_window.upload_virustotal()  # no API key: upload page plus the file in a folder window
    assert said[:2] == ["asked", "info"] and opened[-1] == "https://www.virustotal.com/gui/home/upload"
    assert revealed and revealed[-1].endswith("tool.exe")

    uploaded = []

    def fake_upload(path, key):
        uploaded.append((os.path.basename(path), key))
        return virustotal_result(path)

    monkeypatch.setattr("filespy.virustotal.upload", fake_upload)
    controller.config.detection.virustotal_api_key = "k-1"
    main_window.upload_virustotal()
    assert pump(root, lambda: not main_window.jobs, 10)
    assert uploaded == [("tool.exe", "k-1")] and opened[-1].endswith("/" + "ef" * 32)
    assert "Uploaded tool.exe" in main_window.status.get()

    monkeypatch.setattr("filespy.virustotal.upload", lambda path, key: (_ for _ in ()).throw(
        __import__("filespy.virustotal", fromlist=["x"]).VirusTotalError("quota used up")))
    main_window.upload_virustotal()
    assert pump(root, lambda: not main_window.jobs, 10)
    assert said[-1].endswith("quota used up")

    item = names["notes.txt"]
    main_window.files_tree.selection_set(item)
    root.update()
    assert main_window._selected_sha256() and main_window._selected_path().endswith("notes.txt")
    listed = main_window._selected_sha256()
    (watched / "notes.txt").write_bytes(b"rewritten after it was listed")  # an ordinary edit adds no new row
    main_window.lookup_virustotal()
    assert pump(root, lambda: not main_window.jobs, 10)
    assert opened[-1].endswith("/" + hashlib.sha256(b"rewritten after it was listed").hexdigest())
    os.remove(watched / "notes.txt")
    main_window.lookup_virustotal()  # gone: the page of the content FileSpy recorded
    assert opened[-1].endswith("/" + listed) and "no longer on disk" in main_window.status.get()
    assert main_window.menu.index("end") >= 6 and main_window.vt_menu.index("end") == 1

    dialog = main_window.settings()
    root.update()
    dialog.vt_key.set("  new-key  ")
    dialog.save()
    assert controller.config.detection.virustotal_api_key == "new-key"
    main_window.find.set("notes")
    root.update()
    assert [main_window.files_tree.item(i, "values")[2] for i in main_window.files_tree.get_children()] == ["notes.txt"]


def virustotal_result(path):
    from filespy.virustotal import UploadResult, report_url

    return UploadResult("ef" * 32, "analysis-1", report_url("ef" * 32))
