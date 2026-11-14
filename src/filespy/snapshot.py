"""Before/after snapshots: capture the state of the machine, then show what changed.

Typical use: ``filespy snapshot -o before.json``, run the thing you do not trust,
``filespy snapshot -o after.json``, ``filespy diff before.json after.json``.
"""

from __future__ import annotations

import json
import os
import platform as platform_module
import time
from pathlib import Path
from typing import Any

from filespy import __version__, sanitize
from filespy.autoruns import get_providers as autorun_providers
from filespy.context import Context
from filespy.paths import default_watch_roots, drop_nested, is_excluded, is_within
from filespy.settingsmon import get_providers as settings_providers

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

MAX_FILES = 200000


def _strip_text(value: Any) -> Any:
    """Keep hashes of watched files but not their contents."""
    if isinstance(value, dict) and "hash" in value:
        return {"hash": value["hash"]}
    return value


def _files(ctx: Context, limit: int) -> tuple[dict[str, list[int]], bool]:
    cfg = ctx.config.files
    roots = list(cfg.paths) + (default_watch_roots(ctx.platform) if cfg.use_default_paths else [])
    roots = drop_nested([os.path.abspath(os.path.expanduser(r)) for r in roots if os.path.isdir(os.path.expanduser(r))])
    out: dict[str, list[int]] = {}
    stack = [r for r in roots if not is_within(r, str(ctx.data_dir))]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as iterator:
                for entry in iterator:
                    try:
                        if entry.is_symlink() or is_excluded(entry.path, cfg.exclude):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if cfg.recursive:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            info = entry.stat(follow_symlinks=False)
                            out[entry.path] = [info.st_size, int(info.st_mtime)]
                            if len(out) >= limit:
                                return out, True
                    except OSError:
                        continue
        except OSError:
            continue
    return out, False


def capture(ctx: Context, include_files: bool = True) -> dict[str, Any]:
    snap: dict[str, Any] = {
        "meta": {
            "tool": "FileSpy", "version": __version__, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "host": platform_module.node(), "platform": ctx.platform,
        },
        "autoruns": [], "settings": {}, "processes": [], "listeners": [], "files": {},
    }
    for provider in autorun_providers(ctx):
        try:
            snap["autoruns"].extend(entry.to_dict() for entry in provider.collect())
        except Exception as exc:  # noqa: BLE001 - one unreadable source should not lose the rest
            snap["meta"].setdefault("errors", []).append(f"autoruns/{provider.name}: {exc}")
    for provider in settings_providers(ctx):
        try:
            snap["settings"].update({key: _strip_text(value) for key, value in provider.snapshot().items()})
        except Exception as exc:  # noqa: BLE001
            snap["meta"].setdefault("errors", []).append(f"settings/{provider.name}: {exc}")
    if psutil is not None:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            info = proc.info
            snap["processes"].append({"pid": info["pid"], "name": info["name"] or "", "exe": info["exe"] or "",
                                      "cmdline": " ".join(info["cmdline"] or [])[:1000]})
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    name = ""
                    try:
                        name = psutil.Process(conn.pid).name() if conn.pid else ""
                    except (psutil.Error, OSError):
                        pass
                    snap["listeners"].append({"address": conn.laddr.ip, "port": conn.laddr.port, "pid": conn.pid or 0, "name": name})
        except (psutil.Error, OSError, PermissionError):
            snap["meta"].setdefault("errors", []).append("listeners: not visible without administrator rights")
    if include_files:
        snap["files"], truncated = _files(ctx, MAX_FILES)
        if truncated:
            snap["meta"].setdefault("errors", []).append(f"files: stopped after {MAX_FILES} files")
    return sanitize.json_safe(snap)  # type: ignore[return-value]


def save(snapshot: dict[str, Any], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    return path


def load(path: Path | str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "autoruns" not in data or "meta" not in data:
        raise ValueError(f"{path} is not a FileSpy snapshot")
    return data


def _keyed(items: list[dict[str, Any]], fields: tuple[str, ...]) -> dict[tuple, dict[str, Any]]:
    return {tuple(str(item.get(f, "")).lower() for f in fields): item for item in items}


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """What is new, gone or different in ``after`` compared with ``before``."""
    out: dict[str, Any] = {}
    old_runs = _keyed(before.get("autoruns", []), ("category", "location", "name"))
    new_runs = _keyed(after.get("autoruns", []), ("category", "location", "name"))
    out["autoruns"] = {
        "added": [new_runs[k] for k in new_runs if k not in old_runs],
        "removed": [old_runs[k] for k in old_runs if k not in new_runs],
        "changed": [{"before": old_runs[k], "after": new_runs[k]} for k in new_runs
                    if k in old_runs and old_runs[k].get("command") != new_runs[k].get("command")],
    }
    old_settings, new_settings = before.get("settings", {}), after.get("settings", {})
    out["settings"] = {
        "changed": [{"setting": key, "before": old_settings.get(key), "after": new_settings.get(key)}
                    for key in sorted(set(old_settings) | set(new_settings)) if old_settings.get(key) != new_settings.get(key)],
    }
    old_procs = _keyed(before.get("processes", []), ("name", "exe"))
    new_procs = _keyed(after.get("processes", []), ("name", "exe"))
    out["processes"] = {"added": [new_procs[k] for k in new_procs if k not in old_procs],
                        "removed": [old_procs[k] for k in old_procs if k not in new_procs]}
    old_listen = _keyed(before.get("listeners", []), ("name", "port"))
    new_listen = _keyed(after.get("listeners", []), ("name", "port"))
    out["listeners"] = {"added": [new_listen[k] for k in new_listen if k not in old_listen],
                        "removed": [old_listen[k] for k in old_listen if k not in new_listen]}
    old_files, new_files = before.get("files", {}), after.get("files", {})
    out["files"] = {
        "added": sorted(p for p in new_files if p not in old_files),
        "removed": sorted(p for p in old_files if p not in new_files),
        "modified": sorted(p for p in new_files if p in old_files and old_files[p] != new_files[p]),
    }
    return out


def render_diff(result: dict[str, Any], limit: int = 200) -> str:
    """Plain-text report of a diff, with every value cleaned for the terminal."""
    clean = sanitize.clean
    lines: list[str] = []

    def section(title: str, items: list[str]) -> None:
        if items:
            lines.append(f"{title} ({len(items)})")
            lines.extend(f"  {item}" for item in items[:limit])
            if len(items) > limit:
                lines.append(f"  ... and {len(items) - limit} more")

    runs = result.get("autoruns", {})
    section("New autostart entries", [f"[{clean(e.get('category'), 30)}] {clean(e.get('name'), 80)} -> {clean(e.get('command'), 200)}" for e in runs.get("added", [])])
    section("Changed autostart entries", [f"[{clean(c['after'].get('category'), 30)}] {clean(c['after'].get('name'), 80)}: {clean(c['before'].get('command'), 120)} => {clean(c['after'].get('command'), 120)}" for c in runs.get("changed", [])])
    section("Removed autostart entries", [f"[{clean(e.get('category'), 30)}] {clean(e.get('name'), 80)}" for e in runs.get("removed", [])])
    section("Changed settings", [f"{clean(c['setting'], 80)}: {clean(json.dumps(c['before']), 100)} => {clean(json.dumps(c['after']), 100)}" for c in result.get("settings", {}).get("changed", [])])
    procs = result.get("processes", {})
    section("New programs running", [f"{clean(p.get('name'), 60)}  {clean(p.get('exe'), 200)}" for p in procs.get("added", [])])
    section("Programs no longer running", [f"{clean(p.get('name'), 60)}  {clean(p.get('exe'), 200)}" for p in procs.get("removed", [])])
    section("New listening ports", [f"{clean(item.get('name'), 60)} on {clean(item.get('address'), 60)}:{item.get('port')}" for item in result.get("listeners", {}).get("added", [])])
    files = result.get("files", {})
    section("New files", [clean(p, 300) for p in files.get("added", [])])
    section("Modified files", [clean(p, 300) for p in files.get("modified", [])])
    section("Deleted files", [clean(p, 300) for p in files.get("removed", [])])
    return "\n".join(lines) if lines else "No differences."
