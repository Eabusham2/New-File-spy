import csv
import io
import json
import time
import zipfile

from filespy.config import Config
from filespy.events import Indicator, Severity, make_event
from filespy.export import auto_export, build_meta, export_events, filter_events, render
from filespy.storage import EventStore

EVIL = '=cmd|\' /C calc\'!A0 <script>alert(1)</script> \x1b[31m\u202eexe.txt'


def sample_events():
    return [
        make_event("file", "created", "New program dropped: " + EVIL, "C:\\Temp\\" + EVIL,
                   [Indicator("file.program_in_temp", 40, "A program was written to a temporary folder", "T1105")],
                   {"path": "C:\\Temp\\x.exe", "sha256": "ab" * 32, "raw": b"\x00\x01", "bad": "\udcff"}),
        make_event("process", "started", "Program started: a", "a", [], {"pid": 4, "cmdline": "+SUM(1)"}),
        make_event("setting", "changed", "Defender off", "HKLM\\x",
                   [Indicator("setting.defender", 90, "Real-time protection was turned off", "T1562.001")]),
    ]


def test_store_roundtrip_query_and_prune(tmp_path):
    store = EventStore(tmp_path / "db" / "events.db")
    events = sample_events()
    events[0].session = events[1].session = "s1"
    events[1].ts = events[0].ts  # coarse clocks give events identical times; insertion order must still hold
    events[2].session = "s2"
    events[2].ts = time.time() - 40 * 86400
    for event in events:
        store.add(event)
    store.add(events[0])  # same id: replaced, not duplicated
    assert store.count() == 3
    loaded = store.query(session="s1")
    assert [e.id for e in loaded] == [events[0].id, events[1].id]
    assert loaded[0].indicators[0].id == "file.program_in_temp" and loaded[0].details["sha256"] == "ab" * 32
    assert [e.title for e in store.query(min_severity=Severity.HIGH)] == ["Defender off"]
    assert len(store.query(categories=["file", "process"])) == 2
    assert len(store.query(text="Defender")) == 1
    assert len(store.query(limit=1, newest_first=True)) == 1
    assert {s["session"] for s in store.sessions()} == {"s1", "s2"}
    assert store.prune(retention_days=30, max_events=1000) == 1
    assert store.prune(retention_days=0, max_events=1) == 1 and store.count() == 1
    store.close()


def test_exports_escape_hostile_strings(tmp_path):
    cfg = Config()
    cfg.alerts.webhook_url = "https://hooks.example/secret-token"
    events = sample_events()
    meta = build_meta(events, cfg)
    assert meta["settings"]["alerts"]["webhook_url"] == "<redacted>"

    page = render(events, "html", meta).decode("utf-8")
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "\x1b" not in page and "\u202e" not in page and "secret-token" not in page

    doc = json.loads(render(events, "json", meta))
    assert doc["meta"]["event_count"] == 3 and len(doc["events"]) == 3
    assert doc["events"][0]["details"]["raw"] == "0001"

    rows = list(csv.reader(io.StringIO(render(events, "csv", meta).decode("utf-8-sig"))))
    assert rows[0][0] == "time" and len(rows) == 4
    for row in rows[1:]:
        for cell in row:
            assert cell[:1] not in ("=", "+", "@"), cell
    assert rows[2][10] == "'+SUM(1)"

    lines = render(events, "jsonl", meta).decode().splitlines()
    assert len(lines) == 3 and json.loads(lines[2])["severity"] == "high"

    archive = zipfile.ZipFile(io.BytesIO(render(events, "zip", meta)))
    assert set(archive.namelist()) == {"events.json", "events.csv", "report.html", "settings.json"}

    out = export_events(events, "html", tmp_path / "nested" / "r.html", cfg)
    assert out.exists() and out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_export_settings_filter_and_auto_export(tmp_path):
    cfg = Config()
    events = sample_events()
    assert len(filter_events(events, cfg)) == 2  # quiet process starts are left out by default
    cfg.export.include_info_processes = True
    assert len(filter_events(events, cfg)) == 3
    cfg.export.min_severity = "medium"
    cfg.export.categories = ["setting"]
    assert [e.category for e in filter_events(events, cfg)] == ["setting"]
    cfg.export.formats = ["json", "csv"]
    cfg.export.include_settings = False
    written = auto_export(events, cfg, tmp_path, "abcdef123456")
    assert sorted(p.suffix for p in written) == [".csv", ".json"]
    assert "settings" not in json.loads(written[0].read_text(encoding="utf-8"))["meta"]


def test_export_is_not_redirected_by_a_planted_link_and_leaves_no_temporary_files(tmp_path):
    import sys

    folder = tmp_path / "shared"
    folder.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    if sys.platform != "win32":
        (folder / "report.html.part").symlink_to(victim)  # the old, predictable temporary name
    written = export_events(sample_events(), "html", folder / "report.html", Config())
    assert written.read_text(encoding="utf-8").startswith("<!doctype html>") and victim.read_text() == "keep me"
    assert sorted(p.name for p in folder.iterdir() if not p.is_symlink()) == ["report.html"]
