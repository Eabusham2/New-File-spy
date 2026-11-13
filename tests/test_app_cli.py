import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from filespy.app import App
from filespy.cli import main, parse_since
from filespy.config import Config
from filespy.events import Severity
from filespy.testing import make_pe, test_threat_bytes, wait_for


def quiet_config(watched):
    cfg = Config()
    cfg.files.use_default_paths = False
    cfg.files.paths = [str(watched)]
    cfg.files.settle_seconds = 0.1
    cfg.processes.interval = 0.1
    cfg.alerts.desktop = False
    return cfg


def system_binary():
    """A small real program that keeps running for a while, plus its arguments."""
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return os.path.join(root, "System32", "ping.exe"), ["-n", "30", "127.0.0.1"]
    for candidate in ("/bin/sleep", "/usr/bin/sleep"):
        if os.path.exists(candidate):
            return candidate, ["30"]
    pytest.skip("no sleep binary")


LAUNCHER = "import subprocess, sys; sys.exit(subprocess.call(sys.argv[1:]))"


def kill_tree(process):
    import psutil

    try:
        family = psutil.Process(process.pid).children(recursive=True)
    except psutil.Error:
        family = []
    for member in family:
        try:
            member.kill()
        except psutil.Error:
            pass
    process.kill()
    process.wait()


def test_dropped_program_that_runs_is_tied_together(tmp_path):
    """The headline scenario: a file is dropped, then executed."""
    watched = tmp_path / "drop"
    watched.mkdir()
    app = App(quiet_config(watched), tmp_path / "data", only={"files", "processes"}, console=False)
    app.start()
    launcher = None
    try:
        assert not any(m.failed for m in app.monitors)
        source, arguments = system_binary()
        payload = watched / ("updater.exe" if sys.platform == "win32" else "updater")
        shutil.copy(source, payload)
        # FileSpy ignores its own child processes, so the payload is started by a separate launcher.
        launcher = subprocess.Popen([sys.executable, "-c", LAUNCHER, str(payload), *arguments],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def events(category):
            return [e for e in app.store.query(session=app.session) if e.category == category]

        dropped = wait_for(lambda: [e for e in events("file") if "updater" in e.subject], 30)
        assert dropped, "the dropped program was not reported"
        ran = wait_for(lambda: [e for e in events("process")
                                if any(i.id == "proc.dropped_file_executed" for i in e.indicators)], 30)
        assert ran, "running the dropped program was not reported"
        assert ran[0].severity >= Severity.MEDIUM and "dropped file was executed" in ran[0].title
        assert ran[0].details["name"].lower().startswith("updater")
        assert app.ctx.state.flagged(ran[0].details["pid"]) is not None
    finally:
        if launcher is not None:
            kill_tree(launcher)
        app.stop()


def test_app_stores_exports_and_summarises(tmp_path):
    watched = tmp_path / "drop"
    watched.mkdir()
    cfg = quiet_config(watched)
    cfg.export.auto_on_exit = True
    cfg.export.formats = ["json", "html", "csv"]
    cfg.response.quarantine_min_severity = "critical"
    cfg.alerts.webhook_url = "http://not-allowed.example/hook"
    app = App(cfg, tmp_path / "data", only={"files"}, console=False)
    app.start()
    (watched / "tool.exe").write_bytes(make_pe())
    (watched / "virus.com").write_bytes(test_threat_bytes())
    assert wait_for(lambda: app.counts["critical"] >= 1 and app.counts["medium"] >= 1, 30)
    assert wait_for(lambda: not (watched / "virus.com").exists(), 15), "critical file was not quarantined"
    exported = app.stop()
    assert sorted(p.suffix for p in exported) == [".csv", ".html", ".json"]
    doc = json.loads(next(p for p in exported if p.suffix == ".json").read_text(encoding="utf-8"))
    titles = [e["title"] for e in doc["events"]]
    assert any("tool.exe" in t for t in titles) and any("Quarantined" in t for t in titles)
    assert any("webhook disabled" in t for t in titles)
    assert doc["meta"]["settings"]["alerts"]["webhook_url"] == "<redacted>"
    assert "critical" in app.summary() and (watched / "tool.exe").exists()


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_scan_config_quarantine_and_events(tmp_path, capsys):
    home = str(tmp_path / "home")
    samples = tmp_path / "samples"
    (samples / "sub").mkdir(parents=True)
    (samples / "clean.txt").write_text("hello")
    (samples / "sub" / "bad.com").write_bytes(test_threat_bytes())

    code, out, _ = run(capsys, "--data-dir", home, "scan", str(samples))
    assert code == 0 and "0 flagged" in out
    code, out, _ = run(capsys, "--data-dir", home, "scan", "-r", str(samples))
    assert code == 1 and "CRITICAL" in out and "bad.com" in out and "1 flagged" in out
    code, out, _ = run(capsys, "--data-dir", home, "scan", "-r", "--json", "--all", str(samples))
    assert len(json.loads(out)["results"]) == 2

    assert run(capsys, "--data-dir", home, "config", "set", "export.formats", "csv,zip")[0] == 0
    assert json.loads(run(capsys, "--data-dir", home, "config", "get", "export.formats")[1]) == ["csv", "zip"]
    assert run(capsys, "--data-dir", home, "config", "set", "alerts.webhook_url", "https://h.example/secret")[0] == 0
    backup = str(tmp_path / "settings.json")
    assert run(capsys, "--data-dir", home, "config", "export", backup)[0] == 0
    assert "secret" not in open(backup, encoding="utf-8").read()
    assert run(capsys, "--data-dir", home, "config", "reset")[0] == 0
    assert run(capsys, "--data-dir", home, "config", "import", backup)[0] == 0
    assert json.loads(run(capsys, "--data-dir", home, "config", "get", "export.formats")[1]) == ["csv", "zip"]
    code, _, err = run(capsys, "--data-dir", home, "config", "set", "files.nope", "1")
    assert code == 2 and "no such setting" in err
    code, _, err = run(capsys, "--data-dir", home, "config", "set", "files.recursive", "maybe")
    assert code == 2 and "true or false" in err
    assert "files.settle_seconds" in run(capsys, "--data-dir", home, "config", "keys")[1]

    bad = samples / "sub" / "bad.com"
    code, out, _ = run(capsys, "--data-dir", home, "quarantine", "add", str(bad))
    assert code == 0 and not bad.exists()
    ident = run(capsys, "--data-dir", home, "quarantine", "list")[1].split()[0]
    assert run(capsys, "--data-dir", home, "quarantine", "restore", ident)[0] == 0 and bad.exists()
    assert run(capsys, "--data-dir", home, "quarantine", "restore", "nope")[0] == 2
    assert "empty" in run(capsys, "--data-dir", home, "quarantine", "list")[1]

    assert "No stored events" in run(capsys, "--data-dir", home, "events")[1]
    assert run(capsys, "--data-dir", home, "version")[1].startswith("FileSpy")
    assert run(capsys)[0] == 0


def test_cli_watch_then_events_export_and_sessions(tmp_path, capsys):
    home = str(tmp_path / "home")
    watched = tmp_path / "w"
    watched.mkdir()
    assert run(capsys, "--data-dir", home, "config", "set", "files.settle_seconds", "0.1")[0] == 0

    import threading

    stop = threading.Event()

    def drop():
        count = 0
        while not stop.wait(0.4):  # keep dropping so the test does not depend on start-up speed
            count += 1
            (watched / f"dropped-{count}.exe").write_bytes(make_pe(payload=str(count).encode()))

    dropper = threading.Thread(target=drop, daemon=True)
    dropper.start()
    try:
        code, out, _ = run(capsys, "--data-dir", home, "watch", "--no-defaults", "-p", str(watched), "--only", "files",
                           "--duration", "6", "--no-desktop", "--export", "html,json", "--export-dir", str(tmp_path / "out"))
    finally:
        stop.set()
        dropper.join()
    assert code == 0 and "dropped-" in out and "Exported:" in out and " medium" in out
    assert sorted(p.suffix for p in (tmp_path / "out").iterdir()) == [".html", ".json"]

    code, out, _ = run(capsys, "--data-dir", home, "events", "--severity", "low", "--since", "1h")
    assert "dropped-" in out and "event(s)" in out
    lines = run(capsys, "--data-dir", home, "events", "--json", "--category", "file")[1].splitlines()
    assert json.loads(lines[0])["category"] == "file"
    assert "No stored events" in run(capsys, "--data-dir", home, "events", "--text", "zzzz")[1]
    assert "1" in run(capsys, "--data-dir", home, "sessions")[1]

    target = tmp_path / "report.csv"
    code, out, _ = run(capsys, "--data-dir", home, "export", "-f", "csv", "-o", str(target), "--severity", "medium")
    assert code == 0 and "Exported " in out and "dropped-" in target.read_text(encoding="utf-8-sig")
    assert run(capsys, "--data-dir", home, "export", "-f", "pdf")[0] == 2
    assert run(capsys, "--data-dir", home, "watch", "--only", "bogus", "--duration", "1")[0] == 2


def test_cli_snapshot_diff_autoruns_audit_and_doctor(tmp_path, capsys):
    home = str(tmp_path / "home")
    watched = tmp_path / "w"
    watched.mkdir()
    main(["--data-dir", home, "config", "set", "files.use_default_paths", "false"])
    main(["--data-dir", home, "config", "set", "files.paths", json.dumps([str(watched)])])
    capsys.readouterr()
    before, after = str(tmp_path / "a.json"), str(tmp_path / "b.json")
    assert run(capsys, "--data-dir", home, "snapshot", "-o", before)[0] == 0
    (watched / "new.exe").write_bytes(make_pe())
    assert run(capsys, "--data-dir", home, "snapshot", "-o", after)[0] == 0
    code, out, _ = run(capsys, "--data-dir", home, "diff", before, after)
    assert code == 0 and "New files (1)" in out and "new.exe" in out
    assert "added" in json.loads(run(capsys, "--data-dir", home, "diff", "--json", before, after)[1])["files"]
    assert run(capsys, "--data-dir", home, "diff", before, str(tmp_path / "missing.json"))[0] == 2

    code, out, _ = run(capsys, "--data-dir", home, "autoruns", "--json")
    assert code == 0 and isinstance(json.loads(out), list)
    code, out, _ = run(capsys, "--data-dir", home, "audit", "--json")
    assert code in (0, 1) and isinstance(json.loads(out), list)
    code, out, _ = run(capsys, "--data-dir", home, "doctor")
    assert code == 0 and "data folder is writable" in out


def test_selftest_passes(capsys):
    code, out, _ = run(capsys, "selftest", "--quiet")
    assert code == 0 and "PASS" in out


def test_parse_since():
    assert abs(parse_since("2h") - (time.time() - 7200)) < 5
    assert abs(parse_since("1.5d") - (time.time() - 129600)) < 5
    assert parse_since("2026-01-31T12:00") > 0 and parse_since(None) is None
    with pytest.raises(ValueError):
        parse_since("yesterday-ish")
