"""Windows security settings, driven by the catalog in data/windows_settings.json."""

from __future__ import annotations

import json
import os
from typing import Any

from filespy import sanitize
from filespy.paths import package_data
from filespy.registry import RegistryBackend, _lookup
from filespy.settingsmon import Change
from filespy.settingsmon.danger import evaluate
from filespy.settingsmon.posix import WatchedFile, score_hosts


def load_catalog() -> list[dict[str, Any]]:
    return json.loads(package_data("windows_settings.json").decode("utf-8"))["entries"]


def watched_files(env: dict[str, str] | None = None) -> list[WatchedFile]:
    env = dict(os.environ) if env is None else env
    root = env.get("SystemRoot") or env.get("SYSTEMROOT") or r"C:\Windows"
    etc = os.path.join(root, "System32", "drivers", "etc")
    return [
        WatchedFile("hosts_file", os.path.join(etc, "hosts"), "hosts", "The hosts file was changed", 30, score_hosts, "T1565.001"),
        WatchedFile("hosts_ics_file", os.path.join(etc, "hosts.ics"), "hosts",
                    "The Internet Connection Sharing hosts file was changed", 30, score_hosts, "T1565.001"),
    ]


def _plain(value: Any) -> Any:
    """Make a registry value comparable and JSON-friendly."""
    if isinstance(value, bytes):
        return value[:512].hex()
    if isinstance(value, list):
        return [str(item) for item in value[:200]]
    return value


def _show(value: Any, secret: bool = False) -> str:
    if value is None or value is False:
        return "(not set)"
    if secret:
        return "(hidden)"
    if value is True:
        return "(present)"
    return sanitize.clean(value if isinstance(value, str) else json.dumps(value, default=str), 300)


class WindowsSettingsProvider:
    name = "windows-settings"
    every = 1

    def __init__(self, registry: RegistryBackend, max_tier: int = 2, catalog: list[dict[str, Any]] | None = None) -> None:
        self.reg = registry
        entries = load_catalog() if catalog is None else catalog
        self.entries = {e["id"]: e for e in entries if e.get("tier", 1) <= max_tier}

    def snapshot(self) -> dict[str, Any]:
        cache: dict[tuple[str, str], dict[str, Any] | None] = {}

        def values(hive: str, key: str) -> dict[str, Any] | None:
            if (hive, key) not in cache:
                cache[(hive, key)] = self.reg.values(hive, key)
            return cache[(hive, key)]

        out: dict[str, Any] = {}
        for ident, entry in self.entries.items():
            hive, key, kind = entry["hive"], entry["key"], entry["kind"]
            if kind == "subkeys":
                out[ident] = sorted(self.reg.subkeys(hive, key) or [])
                continue
            found = values(hive, key)
            if kind == "key":
                out[ident] = found is not None
            elif kind == "value_map":
                out[ident] = {name: _plain(data) for name, data in (found or {}).items()}
            elif kind == "service":
                out[ident] = _plain(_lookup(found, "Start"))
            else:
                out[ident] = _plain(_lookup(found, entry.get("value") or ""))
        return out

    def _subject(self, entry: dict[str, Any]) -> str:
        subject = f"{entry['hive']}\\{entry['key']}"
        if entry["kind"] in ("value", "service") and entry.get("value"):
            subject += f"\\{entry['value']}"
        return subject

    def _change(self, entry: dict[str, Any], old: Any, new: Any, danger: bool) -> Change:
        secret = bool(entry.get("secret"))
        details: dict[str, Any] = {"setting": entry["id"], "old": _show(old, secret), "new": _show(new, secret)}
        if isinstance(new, dict) and isinstance(old, dict):
            details["added"] = [sanitize.clean(n, 200) for n in sorted(set(new) - set(old))][:10]
            details["removed"] = [sanitize.clean(n, 200) for n in sorted(set(old) - set(new))][:10]
        elif isinstance(new, list) and isinstance(old, list):
            details["added"] = [sanitize.clean(n, 200) for n in sorted(set(new) - set(old))][:10]
            details["removed"] = [sanitize.clean(n, 200) for n in sorted(set(old) - set(new))][:10]
        if danger:
            title, score = entry["msg"], int(entry.get("score_danger", 60))
        else:
            title = f"A security-related setting changed, not in a dangerous direction ({entry['id']})"
            score = int(entry.get("score_other", 10))
        return Change(entry["id"], entry.get("category", "settings"), title, self._subject(entry), score, danger,
                      entry.get("mitre", ""), details)

    def changes(self, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
        out = []
        for ident, entry in self.entries.items():
            before, after = old.get(ident), new.get(ident)
            if before == after:
                continue
            try:
                danger = evaluate(entry["danger"], entry, before, after, transition=True)
            except Exception:  # noqa: BLE001 - a bad catalog rule must not stop the monitor
                danger = False
            if not danger and not entry.get("score_other"):
                continue  # the catalog says other changes to this setting are of no interest
            out.append(self._change(entry, before, after, danger))
        return out

    def audit(self, snapshot: dict[str, Any]) -> list[Change]:
        out = []
        for ident, entry in self.entries.items():
            value = snapshot.get(ident)
            try:
                danger = evaluate(entry["danger"], entry, value, value, transition=False)
            except Exception:  # noqa: BLE001
                danger = False
            if danger:
                out.append(self._change(entry, value, value, True))
        return out
