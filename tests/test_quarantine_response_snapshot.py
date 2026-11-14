import os
import subprocess
import sys

import pytest

from filespy import snapshot
from filespy.events import Indicator, Severity, make_event
from filespy.quarantine import Quarantine, QuarantineError, link_in_path, remove_exact
from filespy.response import Responder, is_protected
from filespy.testing import make_pe, test_threat_bytes, wait_for


def test_quarantine_round_trip(tmp_path):
    q = Quarantine(tmp_path / "data")
    victim = tmp_path / "evil.exe"
    body = make_pe(payload=b"marker-bytes")
    victim.write_bytes(body)
    record = q.add(str(victim), "test")
    assert not victim.exists() and record.original_removed and record.size == len(body)
    stored = (tmp_path / "data" / "quarantine" / f"{record.id}.bin").read_bytes()
    assert stored != body and not stored.startswith(b"MZ") and b"marker-bytes" not in stored
    assert [r.id for r in q.list()] == [record.id]
    assert q.get(record.id[:8]).id == record.id
    restored = q.restore(record.id)
    assert restored == victim and victim.read_bytes() == body and q.list() == []


def test_quarantine_refuses_unsafe_requests(tmp_path):
    q = Quarantine(tmp_path / "data")
    victim = tmp_path / "a.bin"
    victim.write_bytes(b"one")
    with pytest.raises(QuarantineError):
        q.add(str(victim), expected_sha256="0" * 64)  # changed since it was examined
    assert victim.exists()
    with pytest.raises(QuarantineError):
        q.add(str(tmp_path / "missing"))
    with pytest.raises(QuarantineError):
        q.add(str(tmp_path))  # a directory
    own = tmp_path / "data" / "config.json"
    own.parent.mkdir(parents=True, exist_ok=True)
    own.write_text("{}")
    with pytest.raises(QuarantineError):
        q.add(str(own))
    if sys.platform != "win32":
        link = tmp_path / "link"
        link.symlink_to(victim)
        with pytest.raises(QuarantineError):
            q.add(str(link))
        assert victim.exists()
    record = q.add(str(victim))
    victim.write_bytes(b"new file at the old path")
    with pytest.raises(QuarantineError):
        q.restore(record.id)  # never overwrites
    elsewhere = q.restore(record.id, str(tmp_path / "out" / "a.bin"))
    assert elsewhere.read_bytes() == b"one"
    for bad in ("../../etc/passwd", "zz", "", "0" * 32):
        with pytest.raises(QuarantineError):
            q.delete(bad)
    kept = q.add(str(victim))
    assert q.delete(kept.id).id == kept.id and q.list() == []


@pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX symbolic links")
def test_delete_cannot_be_redirected_by_swapping_the_folder(tmp_path):
    """Between copying a file and deleting it, its folder is replaced by a link to someone else's folder."""
    attacker = tmp_path / "public"
    attacker.mkdir()
    (attacker / "target.dll").write_bytes(b"flagged")
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "target.dll").write_bytes(b"precious")
    copied = os.stat(attacker / "target.dll")
    attacker.rename(tmp_path / "public.moved")
    (tmp_path / "public").symlink_to(protected, target_is_directory=True)
    assert remove_exact(str(tmp_path / "public" / "target.dll"), copied) is False
    assert (protected / "target.dll").read_bytes() == b"precious"
    assert remove_exact(str(tmp_path / "public.moved" / "target.dll"), copied) is True
    assert not (tmp_path / "public.moved" / "target.dll").exists()
    assert remove_exact(str(tmp_path / "nowhere" / "x"), copied) is False


@pytest.mark.skipif(sys.platform == "win32", reason="uses POSIX symbolic links")
def test_restore_refuses_a_folder_that_became_a_link(tmp_path):
    q = Quarantine(tmp_path / "data")
    origin = tmp_path / "downloads"
    origin.mkdir()
    (origin / "evil.exe").write_bytes(b"payload")
    record = q.add(str(origin / "evil.exe"))
    startup = tmp_path / "startup"
    startup.mkdir()
    origin.rmdir()
    origin.symlink_to(startup, target_is_directory=True)
    assert link_in_path(str(origin)) and not link_in_path(str(startup))
    with pytest.raises(QuarantineError, match="link"):
        q.restore(record.id)
    assert list(startup.iterdir()) == [] and len(q.list()) == 1
    safe = q.restore(record.id, str(tmp_path / "inspect" / "evil.bin"))
    assert safe.read_bytes() == b"payload"


def test_protected_processes_are_judged_by_name_and_place():
    assert is_protected("svchost.exe", r"C:\Windows\System32\svchost.exe", "win32")
    assert is_protected("explorer.exe", r"C:\Windows\explorer.exe", "win32")
    assert is_protected("lsass.exe", "", "win32")  # protected processes hide their path
    assert is_protected("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", "win32")
    assert not is_protected("svchost.exe", r"C:\Users\bob\AppData\Local\Temp\svchost.exe", "win32")
    assert not is_protected("notepad.exe", r"C:\Windows\System32\notepad.exe", "win32")
    assert is_protected("systemd", "/usr/lib/systemd/systemd", "linux") and not is_protected("sshd", "/tmp/sshd", "linux")


def test_responder_is_honest_when_the_file_or_process_cannot_be_dealt_with(make_ctx, tmp_path, monkeypatch):
    ctx = make_ctx(response__quarantine_min_severity="high", response__kill_min_severity="high")
    responder = Responder(ctx)
    busy = tmp_path / "running.exe"
    busy.write_bytes(make_pe())
    ctx.state.note_drop(str(busy), "x", "ev", 50)
    monkeypatch.setattr("filespy.quarantine.remove_exact", lambda path, opened: False)  # e.g. the program is running
    hot = [Indicator("x", 80, "r")]
    responder.handle(make_event("file", "created", "busy", str(busy), hot, {"path": str(busy)}))
    said = ctx.bus.find("system", "response")[-1]
    assert "Could not remove" in said.title and said.severity is Severity.HIGH
    assert busy.exists() and Quarantine(ctx.data_dir).list() == [] and ctx.state.lookup_drop(str(busy)) is not None
    responder.handle(make_event("process", "started", "unknown start", "x", hot, {"pid": 999999, "name": "x.exe"}))
    assert "start time is unknown" in ctx.bus.find("system", "response")[-1].title


def test_responder_is_off_by_default_and_quarantines_when_enabled(make_ctx, tmp_path):
    ctx = make_ctx()
    assert not Responder(ctx).enabled
    ctx = make_ctx(response__quarantine_min_severity="high")
    responder = Responder(ctx)
    ctx.bus.subscribe(responder.handle)
    low = tmp_path / "ok.exe"
    low.write_bytes(make_pe())
    ctx.bus.publish(make_event("file", "created", "low", str(low), [Indicator("x", 30, "r")], {"path": str(low)}))
    assert low.exists()
    bad = tmp_path / "bad.com"
    bad.write_bytes(test_threat_bytes())
    report = ctx.analyzer.analyze(str(bad))
    ctx.bus.publish(make_event("file", "created", "bad", str(bad), report.indicators, report.to_details()))
    assert not bad.exists()
    responses = ctx.bus.find("system", "response")
    assert responses and "Quarantined" in responses[0].title and len(Quarantine(ctx.data_dir).list()) == 1
    gone = make_event("file", "created", "gone", str(tmp_path / "nope"), [Indicator("x", 100, "r")], {"path": str(tmp_path / "nope")})
    ctx.bus.publish(gone)
    assert "Could not quarantine" in ctx.bus.find("system", "response")[-1].title


def test_responder_kills_only_the_exact_process(make_ctx):
    import psutil

    ctx = make_ctx(response__kill_min_severity="high")
    responder = Responder(ctx)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        info = psutil.Process(child.pid)
        details = {"pid": child.pid, "create_time": info.create_time(), "name": info.name()}
        hot = [Indicator("x", 80, "r")]
        responder.handle(make_event("process", "started", "wrong time", "x", hot, {**details, "create_time": 1.0}))
        responder.handle(make_event("process", "started", "protected", "x", hot, {**details, "name": "lsass.exe"}))
        responder.handle(make_event("process", "started", "ours", "x", hot, {**details, "pid": os.getpid()}))
        responder.handle(make_event("process", "started", "too mild", "x", [Indicator("x", 30, "r")], details))
        assert child.poll() is None
        responder.handle(make_event("process", "started", "real", "x", hot, details))
        assert wait_for(lambda: child.poll() is not None, 10)
        assert any("Stopped" in e.title for e in ctx.bus.find("system", "response"))
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def test_snapshot_diff(make_ctx, tmp_path):
    watched = tmp_path / "w"
    watched.mkdir()
    (watched / "old.txt").write_text("1")
    (watched / "gone.txt").write_text("1")
    ctx = make_ctx()
    ctx.config.files.paths = [str(watched)]
    before = snapshot.capture(ctx)
    assert before["meta"]["tool"] == "FileSpy" and str(watched / "old.txt") in before["files"]
    assert before["processes"] and isinstance(before["autoruns"], list)
    saved = snapshot.save(before, tmp_path / "snaps" / "before.json")
    assert snapshot.load(saved)["files"] == before["files"]
    with pytest.raises(ValueError):
        snapshot.load(snapshot.save({"x": 1}, tmp_path / "bad.json"))

    after = snapshot.load(saved)
    after["files"][str(watched / "new\x1b[31m.exe")] = [10, 5]
    del after["files"][str(watched / "gone.txt")]
    after["files"][str(watched / "old.txt")] = [99, 9]
    after["autoruns"].append({"category": "cron", "location": "/etc/cron.d/x", "name": "job", "command": "/tmp/x", "target": "/tmp/x"})
    after["settings"]["hosts_file"] = {"hash": "different"}
    after["processes"].append({"pid": 1, "name": "evil", "exe": "/tmp/evil", "cmdline": ""})
    after["listeners"].append({"address": "0.0.0.0", "port": 4444, "pid": 1, "name": "evil"})
    result = snapshot.diff(before, after)
    assert len(result["files"]["added"]) == 1 and result["files"]["removed"] == [str(watched / "gone.txt")]
    assert result["files"]["modified"] == [str(watched / "old.txt")]
    assert result["autoruns"]["added"][0]["name"] == "job" and result["processes"]["added"][0]["name"] == "evil"
    assert result["listeners"]["added"][0]["port"] == 4444
    assert any(c["setting"] == "hosts_file" for c in result["settings"]["changed"])
    text = snapshot.render_diff(result)
    assert "New autostart entries (1)" in text and "4444" in text and "\x1b" not in text
    assert snapshot.render_diff(snapshot.diff(before, before)) == "No differences."
