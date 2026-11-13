"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import platform as platform_module
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from filespy import __version__, sanitize
from filespy.alerts import format_event
from filespy.config import Config, config_path, load_config, save_config
from filespy.events import Event, Severity, severity_for, summarize
from filespy.paths import data_dir as default_data_dir
from filespy.paths import default_watch_roots, ensure_private_dir

SEVERITIES = [s.label for s in Severity]


def _setup(args: argparse.Namespace) -> tuple[Path, Config, Path]:
    home = Path(args.data_dir) if args.data_dir else default_data_dir()
    cfg_file = Path(args.config) if args.config else config_path(home)
    return home, load_config(cfg_file), cfg_file


def _out(text: str = "") -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "ascii"
        print(text.encode(encoding, "backslashreplace").decode(encoding))


def parse_since(value: str | None) -> float | None:
    """"30m", "2h", "7d" (ago) or an ISO date/time -> epoch seconds."""
    if not value:
        return None
    text = value.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if text[-1:] in units and text[:-1].replace(".", "", 1).isdigit():
        return time.time() - float(text[:-1]) * units[text[-1]]
    try:
        return datetime.fromisoformat(value.strip()).timestamp()
    except ValueError:
        raise ValueError(f"cannot understand time {value!r}; use 30m, 2h, 7d or 2026-01-31T12:00") from None


def _names(value: str | None) -> set[str] | None:
    return {part.strip() for part in value.split(",") if part.strip()} if value else None


# ---------------------------------------------------------------------------- watch
def cmd_watch(args: argparse.Namespace) -> int:
    from filespy.app import MONITORS, App, is_admin

    home, cfg, _ = _setup(args)
    if args.path:
        cfg.files.paths = list(cfg.files.paths) + [os.path.abspath(p) for p in args.path]
    if args.no_defaults:
        cfg.files.use_default_paths = False
    if args.min_severity:
        cfg.general.min_severity = args.min_severity
    if args.verbose:
        cfg.general.min_severity = "info"
    if args.no_desktop:
        cfg.alerts.desktop = False
    if args.export:
        cfg.export.auto_on_exit = True
        cfg.export.formats = sorted(_names(args.export) or [])
    if args.export_dir:
        cfg.export.directory = os.path.abspath(args.export_dir)
    cfg.validate()
    only, skip = _names(args.only), _names(args.skip) or set()
    unknown = ((only or set()) | skip) - set(MONITORS)
    if unknown:
        raise ValueError(f"unknown monitor(s): {', '.join(sorted(unknown))}; choose from {', '.join(MONITORS)}")
    selected = {name for name in MONITORS if (only is None or name in only) and name not in skip}
    chatty = not (args.json or args.quiet)
    app = App(cfg, home, only=selected, console=not args.quiet, as_json=args.json)
    if chatty:
        _out(f"FileSpy {__version__}  -  session {app.session}  -  data folder: {home}")
        if not is_admin():
            _out("Not running as administrator: other users' programs and some system locations may not be visible.")
        _out("Taking a baseline of the current state, then watching. Press Ctrl+C to stop.\n")
    exported = app.run(args.duration)
    if chatty:
        _out("\nStopped. " + app.summary())
        for path in exported:
            _out(f"Exported: {path}")
        _out(f"Look back any time with:  filespy events --session {app.session}")
    return 0


# ---------------------------------------------------------------------------- scan
def _walk(paths: list[str], recursive: bool, limit: int = 100000) -> list[str]:
    out: list[str] = []
    for path in paths:
        if os.path.isdir(path) and not os.path.islink(path):
            if not recursive:
                out.extend(e.path for e in os.scandir(path) if e.is_file(follow_symlinks=False))
                continue
            for folder, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d))]
                out.extend(os.path.join(folder, name) for name in files)
                if len(out) >= limit:
                    return out[:limit]
        else:
            out.append(path)
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    from filespy.analyzer import FileAnalyzer

    _home, cfg, _ = _setup(args)
    analyzer = FileAnalyzer(cfg.detection)
    minimum = Severity.parse(args.min_severity or "low")
    worst, results, scanned = Severity.INFO, [], 0
    for path in _walk(args.paths, args.recursive):
        report = analyzer.analyze(path)
        scanned += 1
        score, severity = summarize(report.indicators)
        if report.error and not report.exists:
            results.append({"path": path, "error": report.error})
            continue
        if severity >= minimum or args.all:
            worst = max(worst, severity)
            results.append({"path": path, "severity": severity.label, "score": score, "kind": report.kind,
                            "sha256": report.sha256, "size": report.size,
                            "indicators": [i.to_dict() for i in report.indicators]})
    if args.json:
        _out(json.dumps(sanitize.json_safe({"scanned": scanned, "results": results}), indent=2))
    else:
        for item in results:
            if "error" in item:
                _out(f"ERROR     {sanitize.clean(item['path'], 300)}: {item['error']}")
                continue
            _out(f"{item['severity'].upper():<9} {sanitize.clean(item['path'], 300)}  [{item['kind']}, {item['size']:,} bytes]")
            for indicator in item["indicators"]:
                _out(f"          - {sanitize.clean(indicator['description'], 300)}")
            if item["sha256"] and item["indicators"]:
                _out(f"          sha256 {item['sha256']}")
        flagged = sum(1 for item in results if item.get("indicators"))
        _out(f"\nScanned {scanned} file(s); {flagged} flagged.")
    return 1 if worst >= Severity.MEDIUM else 0


# ---------------------------------------------------------------------------- stored events
def _query(args: argparse.Namespace, home: Path) -> list[Event]:
    from filespy.storage import EventStore

    database = home / "events.db"
    if not database.exists():
        return []
    store = EventStore(database)
    try:
        return store.query(
            since=parse_since(getattr(args, "since", None)),
            min_severity=Severity.parse(getattr(args, "severity", None) or "info"),
            categories=getattr(args, "category", None) or None,
            session=getattr(args, "session", None),
            text=getattr(args, "text", None),
            limit=getattr(args, "limit", None),
            newest_first=bool(getattr(args, "limit", None)),
        )
    finally:
        store.close()


def cmd_events(args: argparse.Namespace) -> int:
    home, _cfg, _ = _setup(args)
    events = sorted(_query(args, home), key=lambda e: e.ts)
    if args.json:
        for event in events:
            _out(json.dumps(sanitize.json_safe(event.to_dict())))
        return 0
    if not events:
        _out("No stored events match.")
        return 0
    for event in events:
        _out(time.strftime("%Y-%m-%d ", time.localtime(event.ts)) + format_event(event, False))
    _out(f"\n{len(events)} event(s).")
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    from filespy.storage import EventStore

    home, _cfg, _ = _setup(args)
    if not (home / "events.db").exists():
        _out("No sessions recorded yet.")
        return 0
    store = EventStore(home / "events.db")
    try:
        rows = store.sessions(args.limit)
    finally:
        store.close()
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        start = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["start"]))
        minutes = (row["end"] - row["start"]) / 60
        _out(f"{row['session']:<14} {start}  {minutes:6.1f} min  {row['events']:6d} events  worst: {row['max_severity']}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from filespy.export import FORMATS, export_events, filter_events

    home, cfg, _ = _setup(args)
    if args.severity:
        cfg.export.min_severity = args.severity
    if args.category:
        cfg.export.categories = list(args.category)
    if args.all_processes:
        cfg.export.include_info_processes = True
    if args.no_settings:
        cfg.export.include_settings = False
    cfg.validate()
    fmt = args.format or (cfg.export.formats[0] if cfg.export.formats else "html")
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    args.severity = None  # filtering is done by the export settings below
    args.category = None
    events = filter_events(sorted(_query(args, home), key=lambda e: e.ts), cfg)
    folder = Path(cfg.export.directory) if cfg.export.directory else home / "exports"
    target = Path(args.output) if args.output else folder / f"filespy-{time.strftime('%Y%m%d-%H%M%S')}.{fmt}"
    filters = {"since": args.since or "", "session": args.session or "", "min_severity": cfg.export.min_severity,
               "categories": cfg.export.categories}
    written = export_events(events, fmt, target, cfg, filters)
    _out(f"Exported {len(events)} event(s) to {written}")
    return 0


# ---------------------------------------------------------------------------- current state
def _context(args: argparse.Namespace):  # noqa: ANN202
    from filespy.context import Context
    from filespy.events import EventBus
    from filespy.registry import make_registry

    home, cfg, _ = _setup(args)
    return Context(cfg, EventBus("cli"), ensure_private_dir(home), registry=make_registry())


def cmd_autoruns(args: argparse.Namespace) -> int:
    from filespy.autoruns import get_providers, label

    ctx = _context(args)
    entries = []
    for provider in get_providers(ctx):
        try:
            entries.extend(provider.collect())
        except Exception as exc:  # noqa: BLE001
            print(f"filespy: could not read {provider.name}: {exc}", file=sys.stderr)
    entries.sort(key=lambda e: (e.category, e.location.lower(), e.name.lower()))
    if args.json:
        _out(json.dumps(sanitize.json_safe([e.to_dict() for e in entries]), indent=2))
        return 0
    current = None
    for entry in entries:
        if entry.category != current:
            current = entry.category
            _out(f"\n== {label(current)} ==")
        _out(f"  {sanitize.clean(entry.name, 70):<40} {sanitize.clean(entry.command, 160)}")
    _out(f"\n{len(entries)} autostart entries.")
    return 0


ALWAYS_SUSPECT = {"ifeo", "silent_exit", "appinit", "appcert", "ld_preload", "login_hook"}


def collect_audit(ctx) -> list[dict[str, Any]]:  # noqa: ANN001
    """Things that look wrong right now: autostart entries, settings and running programs."""
    from filespy.autoruns import get_providers as autorun_providers
    from filespy.autoruns import label, score_entry
    from filespy.monitors.processes import psutil, snapshot
    from filespy.procrules import evaluate
    from filespy.settingsmon import get_providers as settings_providers

    findings: list[dict[str, Any]] = []
    for provider in autorun_providers(ctx):
        try:
            entries = provider.collect()
        except Exception:  # noqa: BLE001
            continue
        for entry in entries:
            indicators = score_entry(entry, ctx, deep=False)
            if entry.category not in ALWAYS_SUSPECT:
                indicators = [i for i in indicators if i.id != f"autorun.{entry.category}"]
            score, severity = summarize(indicators)
            if indicators and score >= 20:
                findings.append({"area": "autorun", "severity": severity.label, "score": score,
                                 "title": f"{label(entry.category)}: {entry.name}", "subject": entry.command,
                                 "reasons": [i.description for i in indicators]})
    for provider in settings_providers(ctx):
        try:
            changes = provider.audit(provider.snapshot())
        except Exception:  # noqa: BLE001
            continue
        for change in changes:
            findings.append({"area": "setting", "severity": severity_for(change.score).label, "score": change.score,
                             "title": change.title, "subject": change.subject, "reasons": []})
    if psutil is not None:
        own = os.getpid()
        for pid in psutil.pids():
            info = snapshot(pid)
            if info is None or pid == own or info.ppid == own:
                continue
            indicators = evaluate(info, ctx.platform, None, young_minutes=0)
            score, severity = summarize(indicators)
            if score >= 40:
                findings.append({"area": "process", "severity": severity.label, "score": score,
                                 "title": f"{info.name} (pid {pid})", "subject": info.exe or info.command,
                                 "reasons": [i.description for i in indicators]})
    findings.sort(key=lambda f: -f["score"])
    return findings


def cmd_audit(args: argparse.Namespace) -> int:
    findings = collect_audit(_context(args))
    if args.json:
        _out(json.dumps(sanitize.json_safe(findings), indent=2))
    elif not findings:
        _out("Nothing suspicious found in the current autostart entries, settings or running programs.")
    else:
        for item in findings:
            _out(f"{item['severity'].upper():<9} {item['area']:<8} {sanitize.clean(item['title'], 200)}")
            _out(f"          {sanitize.clean(item['subject'], 300)}")
            for reason in item["reasons"]:
                _out(f"          - {sanitize.clean(reason, 300)}")
        _out(f"\n{len(findings)} finding(s). These are things worth a look, not proof of infection.")
    return 1 if any(Severity.parse(f["severity"]) >= Severity.MEDIUM for f in findings) else 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    from filespy import snapshot

    ctx = _context(args)
    target = Path(args.output) if args.output else ctx.data_dir / "snapshots" / f"snapshot-{time.strftime('%Y%m%d-%H%M%S')}.json"
    data = snapshot.capture(ctx, include_files=not args.no_files)
    snapshot.save(data, target)
    _out(f"Snapshot saved to {target}")
    _out(f"  {len(data['autoruns'])} autostart entries, {len(data['settings'])} settings, "
         f"{len(data['processes'])} programs, {len(data['listeners'])} listening ports, {len(data['files'])} files")
    for problem in data["meta"].get("errors", []):
        _out(f"  note: {problem}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from filespy import snapshot

    result = snapshot.diff(snapshot.load(args.before), snapshot.load(args.after))
    _out(json.dumps(result, indent=2) if args.json else snapshot.render_diff(result))
    return 0


# ---------------------------------------------------------------------------- quarantine
def cmd_quarantine(args: argparse.Namespace) -> int:
    from filespy.quarantine import Quarantine

    home, _cfg, _ = _setup(args)
    quarantine = Quarantine(ensure_private_dir(home))
    if args.action == "list":
        records = quarantine.list()
        if not records:
            _out("Quarantine is empty.")
        for record in records:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(record.ts))
            _out(f"{record.id[:12]}  {when}  {record.size:>10,} bytes  {sanitize.clean(record.original_path, 200)}")
    elif args.action == "add":
        record = quarantine.add(args.target)
        _out(f"Quarantined as {record.id[:12]} (sha256 {record.sha256})")
        if not record.original_removed:
            _out("The original could not be removed; a copy is in quarantine.")
    elif args.action == "restore":
        _out(f"Restored to {quarantine.restore(args.target, args.to)}")
    elif args.action == "delete":
        record = quarantine.delete(args.target)
        _out(f"Deleted quarantined copy of {sanitize.clean(record.original_path, 200)}")
    return 0


# ---------------------------------------------------------------------------- config
def cmd_config(args: argparse.Namespace) -> int:
    _home, cfg, cfg_file = _setup(args)
    action = args.action
    if action == "path":
        _out(str(cfg_file))
    elif action == "show":
        _out(json.dumps(cfg.to_dict(redact=not args.secrets), indent=2))
    elif action == "keys":
        for key in cfg.keys():
            _out(f"{key} = {json.dumps(cfg.get(key))}")
    elif action == "get":
        _out(json.dumps(cfg.get(args.key)))
    elif action == "set":
        cfg.set(args.key, args.value)
        save_config(cfg, cfg_file)
        _out(f"{args.key} = {json.dumps(cfg.get(args.key))}")
    elif action == "export":
        save_config(cfg, args.file, redact=not args.secrets)
        _out(f"Settings written to {args.file}")
    elif action == "import":
        if not os.path.isfile(args.file):
            raise ValueError(f"no such file: {args.file}")
        imported = load_config(args.file)
        save_config(imported, cfg_file)
        cfg = imported
        _out(f"Settings imported from {args.file}")
    elif action == "reset":
        cfg = Config()
        save_config(cfg, cfg_file)
        _out("Settings reset to defaults.")
    for warning in cfg.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------- doctor / selftest
def cmd_doctor(args: argparse.Namespace) -> int:
    from filespy.alerts import notification_command
    from filespy.app import is_admin
    from filespy.registry import make_registry

    home, cfg, cfg_file = _setup(args)
    problems = 0

    def line(ok: bool | None, text: str) -> None:
        nonlocal problems
        problems += ok is False
        _out(f"[{'ok' if ok else ' !' if ok is False else '--'}] {text}")

    _out(f"FileSpy {__version__} on Python {platform_module.python_version()} / {platform_module.system()} {platform_module.release()}")
    line(True if is_admin() else None, "running as administrator" if is_admin() else
         "not running as administrator (works, but sees less: other users' programs, some system locations)")
    for module, purpose in (("psutil", "process and network monitoring"), ("watchdog", "real-time file events (polling is used without it)")):
        try:
            __import__(module)
            line(True, f"{module} is installed ({purpose})")
        except ImportError:
            line(False if module == "psutil" else None, f"{module} is NOT installed: {purpose}. Install with: pip install {module}")
    try:
        ensure_private_dir(home)
        probe = home / ".write-test"
        probe.write_text("x")
        probe.unlink()
        line(True, f"data folder is writable: {home}")
    except OSError as exc:
        line(False, f"data folder is not writable: {home} ({exc})")
    line(not cfg.warnings, f"configuration: {cfg_file}" + ("" if not cfg.warnings else f" ({len(cfg.warnings)} warning(s))"))
    for warning in cfg.warnings:
        _out(f"       {warning}")
    roots = list(cfg.files.paths) + (default_watch_roots() if cfg.files.use_default_paths else [])
    present = [r for r in roots if os.path.isdir(os.path.expanduser(r))]
    line(bool(present), f"{len(present)} of {len(roots)} folders to watch exist")
    if os.name == "nt":
        line(make_registry() is not None, "Windows registry is readable")
    line(True if notification_command("t", "b") else None, "desktop notifications available" if notification_command("t", "b")
         else "desktop notifications unavailable (install notify-send); alerts still appear in the console")
    _out("\nEverything needed is in place." if not problems else f"\n{problems} problem(s) need attention.")
    return 1 if problems else 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Prove that alerts fire, using harmless test files in a private temporary folder."""
    from filespy.app import App
    from filespy.testing import eicar_bytes, make_pe, test_threat_bytes, wait_for

    work = Path(tempfile.mkdtemp(prefix="filespy-selftest-"))
    watched = work / "watched"
    watched.mkdir()
    cfg = Config()
    cfg.files.use_default_paths = False
    cfg.files.paths = [str(watched)]
    cfg.alerts.desktop = cfg.alerts.log_file = False
    cfg.general.min_severity = "low"
    app = App(cfg, work / "data", only={"files"}, console=not args.quiet)
    passed = False
    try:
        app.start()
        _out("Dropping three harmless test files: a dummy program, FileSpy's own test marker, and the EICAR antivirus test file...")
        (watched / "filespy-test-program.exe").write_bytes(make_pe())
        (watched / "filespy-test-marker.bin").write_bytes(test_threat_bytes())
        try:
            (watched / "filespy-eicar-test.com").write_bytes(eicar_bytes())
        except OSError:
            pass  # an antivirus may block the write; the marker file is the real test

        def critical(name: str) -> bool:
            return any(e.category == "file" and name in e.subject and e.severity is Severity.CRITICAL
                       for e in app.store.query(session=app.session))

        passed = bool(wait_for(lambda: critical("filespy-test-marker"), 30, 0.25))
        if passed:
            wait_for(lambda: critical("filespy-eicar-test"), 5, 0.25)
            _out("\nPASS: the dropped test file was detected and reported as CRITICAL.")
            if not critical("filespy-eicar-test"):
                _out("(The EICAR file was not reported: your antivirus most likely removed it first, which is fine.)")
        else:
            _out("\nFAIL: no alert was raised for the test file within 30 seconds. Run 'filespy doctor'.")
    finally:
        app.stop()
        shutil.rmtree(work, ignore_errors=True)
    return 0 if passed else 1


def cmd_version(_args: argparse.Namespace) -> int:
    _out(f"FileSpy {__version__}")
    return 0


# ---------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filespy",
        description="Watches for dropped files, autostart and security-setting changes and suspicious programs, and tells you.",
    )
    parser.add_argument("--version", action="version", version=f"FileSpy {__version__}")
    parser.add_argument("--data-dir", help="folder for settings, the event database, logs and quarantine")
    parser.add_argument("--config", help="settings file to use instead of the one in the data folder")
    sub = parser.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("watch", help="monitor this computer live (the main command)")
    p.add_argument("-p", "--path", action="append", help="extra folder to watch (repeatable)")
    p.add_argument("--no-defaults", action="store_true", help="watch only the folders given with --path")
    p.add_argument("--only", help="comma-separated monitors to run: files,processes,network,autoruns,settings")
    p.add_argument("--skip", help="comma-separated monitors to leave out")
    p.add_argument("--min-severity", choices=SEVERITIES, help="lowest severity to print (default: low)")
    p.add_argument("-v", "--verbose", action="store_true", help="print everything, including informational events")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing; events are still stored")
    p.add_argument("--json", action="store_true", help="print events as JSON lines")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--export", help="when stopping, export this session in these formats (comma-separated: json,jsonl,csv,html,zip)")
    p.add_argument("--export-dir", help="folder for the exported files")
    p.add_argument("--no-desktop", action="store_true", help="no desktop notifications")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("scan", help="examine files or folders once")
    p.add_argument("paths", nargs="+")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("--all", action="store_true", help="list every file, not only flagged ones")
    p.add_argument("--min-severity", choices=SEVERITIES)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    def filters(target: argparse.ArgumentParser) -> None:
        target.add_argument("--since", help="how far back: 30m, 2h, 7d or a date/time")
        target.add_argument("--severity", choices=SEVERITIES, help="lowest severity to include")
        target.add_argument("--category", action="append", choices=["file", "process", "network", "autorun", "setting", "system"])
        target.add_argument("--session", help="only this watch session")
        target.add_argument("--text", help="only events whose title or subject contains this")

    p = sub.add_parser("events", help="show stored events")
    filters(p)
    p.add_argument("--limit", type=int, help="newest N events")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("sessions", help="list past watch sessions")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("export", help="export stored events to json, jsonl, csv, html or zip")
    p.add_argument("-f", "--format", help="json, jsonl, csv, html or zip (default: first format in the settings)")
    p.add_argument("-o", "--output", help="file to write (default: the exports folder)")
    filters(p)
    p.add_argument("--all-processes", action="store_true", help="include unremarkable program starts")
    p.add_argument("--no-settings", action="store_true", help="do not embed the settings in the export")
    p.set_defaults(func=cmd_export, limit=None)

    p = sub.add_parser("autoruns", help="list everything set to start automatically")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_autoruns)

    p = sub.add_parser("audit", help="check current autostart entries, settings and running programs for trouble")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("snapshot", help="save the current state for a later diff")
    p.add_argument("-o", "--output")
    p.add_argument("--no-files", action="store_true", help="skip the file listing")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("diff", help="compare two snapshots")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("quarantine", help="list, add, restore or delete quarantined files")
    p.add_argument("action", choices=["list", "add", "restore", "delete"])
    p.add_argument("target", nargs="?", help="file to quarantine, or the id to restore or delete")
    p.add_argument("--to", help="restore to this path instead of the original one")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("config", help="show or change settings; export and import them")
    p.add_argument("action", choices=["path", "show", "keys", "get", "set", "export", "import", "reset"])
    p.add_argument("key", nargs="?", help="section.key for get/set, or a file for export/import")
    p.add_argument("value", nargs="?")
    p.add_argument("--secrets", action="store_true", help="include the webhook address and API key instead of hiding them")
    p.set_defaults(func=cmd_config)

    sub.add_parser("doctor", help="check that everything FileSpy needs is in place").set_defaults(func=cmd_doctor)
    p = sub.add_parser("selftest", help="prove that alerts fire, using a harmless test file")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_selftest)
    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    from filespy.quarantine import QuarantineError

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    if args.command == "quarantine" and args.action != "list" and not args.target:
        parser.error(f"quarantine {args.action} needs a file or an id")
    if args.command == "config":
        needs = {"get": 1, "set": 2, "export": 1, "import": 1}.get(args.action, 0)
        if needs >= 1 and not args.key or needs == 2 and args.value is None:
            parser.error(f"config {args.action} needs {'a key and a value' if needs == 2 else 'an argument'}")
        args.file = args.key
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except KeyError as exc:
        print(f"filespy: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 2
    except (QuarantineError, ValueError, OSError) as exc:
        print(f"filespy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
