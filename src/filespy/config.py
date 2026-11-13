"""Configuration: typed defaults, JSON load/save, dotted-key get/set, export/import."""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filespy.events import Severity

CONFIG_VERSION = 1
SECRET_KEYS = ("alerts.webhook_url", "detection.virustotal_api_key")

DEFAULT_EXCLUDES = [
    # Browser profiles and caches: constant churn, and downloads land in Downloads anyway.
    "*/google/chrome/user data/*",
    "*/microsoft/edge/user data/*",
    "*/bravesoftware/*/user data/*",
    "*/mozilla/firefox/profiles/*",
    "*/.mozilla/firefox/*",
    "*/.config/google-chrome/*",
    "*/.config/chromium/*",
    "*/.cache/mozilla/*",
    "*/.cache/google-chrome/*",
    "*/.cache/chromium/*",
    "*/library/caches/google/*",
    "*/library/caches/firefox/*",
    # Windows shell and app-container noise.
    "*/appdata/local/packages/*",
    "*/appdata/local/microsoft/windows/webcache/*",
    "*/appdata/local/microsoft/windows/explorer/*",
    "*/appdata/local/microsoft/windows/notifications/*",
    "*/appdata/local/d3dscache/*",
    "*/appdata/local/connecteddevicesplatform/*",
    # Developer trees.
    "*/.git/*",
    "*/node_modules/*",
    "*/__pycache__/*",
    "*/.pytest_cache/*",
]


@dataclass
class GeneralCfg:
    min_severity: str = "low"  # lowest severity printed on the console


@dataclass
class FilesCfg:
    enabled: bool = True
    use_default_paths: bool = True
    paths: list[str] = field(default_factory=list)  # extra directories to watch
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    recursive: bool = True
    backend: str = "auto"  # auto | watchdog | polling
    report_all: bool = False  # also record ordinary (non-executable) files at INFO
    settle_seconds: float = 1.0
    max_settle_seconds: float = 20.0
    poll_interval: float = 2.0
    rescan_interval: float = 60.0
    burst_threshold: int = 40  # renames/rewrites of user files inside burst_window
    burst_window: float = 10.0


@dataclass
class AutorunsCfg:
    enabled: bool = True
    interval: float = 5.0
    scheduled_tasks: bool = True
    services: bool = True


@dataclass
class SettingsCfg:
    enabled: bool = True
    interval: float = 10.0
    max_tier: int = 2  # 1 = essentials only, 3 = everything in the catalog


@dataclass
class ProcessesCfg:
    enabled: bool = True
    interval: float = 0.5
    young_image_minutes: float = 15.0
    record_all: bool = False  # store every process start, not only suspicious ones
    ignore_names: list[str] = field(default_factory=list)


@dataclass
class NetworkCfg:
    enabled: bool = True
    interval: float = 3.0
    report_listeners: bool = True


@dataclass
class DetectionCfg:
    max_scan_mb: int = 32  # bytes of each file searched for signatures
    max_hash_mb: int = 512  # larger files are not hashed
    entropy_threshold: float = 7.2
    rules_files: list[str] = field(default_factory=list)  # extra JSON rule files
    hash_blocklists: list[str] = field(default_factory=list)  # text files, one hash per line
    hash_allowlists: list[str] = field(default_factory=list)
    yara_rules_dir: str = ""
    virustotal: bool = False  # hash-only lookup, off by default
    virustotal_api_key: str = ""  # or environment variable FILESPY_VT_KEY


@dataclass
class AlertsCfg:
    console: bool = True
    color: str = "auto"  # auto | always | never
    log_file: bool = True
    desktop: bool = True
    desktop_min_severity: str = "high"
    sound: bool = False
    webhook_url: str = ""
    webhook_min_severity: str = "high"
    max_desktop_per_minute: int = 6


@dataclass
class ExportCfg:
    auto_on_exit: bool = False
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    directory: str = ""  # empty = <data dir>/exports
    min_severity: str = "info"
    categories: list[str] = field(default_factory=list)  # empty = all
    include_settings: bool = True
    include_info_processes: bool = False


@dataclass
class ResponseCfg:
    quarantine_min_severity: str = ""  # empty = never quarantine automatically
    kill_min_severity: str = ""  # empty = never kill automatically


@dataclass
class StorageCfg:
    retention_days: int = 30
    max_events: int = 200000


@dataclass
class Config:
    version: int = CONFIG_VERSION
    general: GeneralCfg = field(default_factory=GeneralCfg)
    files: FilesCfg = field(default_factory=FilesCfg)
    autoruns: AutorunsCfg = field(default_factory=AutorunsCfg)
    settings: SettingsCfg = field(default_factory=SettingsCfg)
    processes: ProcessesCfg = field(default_factory=ProcessesCfg)
    network: NetworkCfg = field(default_factory=NetworkCfg)
    detection: DetectionCfg = field(default_factory=DetectionCfg)
    alerts: AlertsCfg = field(default_factory=AlertsCfg)
    export: ExportCfg = field(default_factory=ExportCfg)
    response: ResponseCfg = field(default_factory=ResponseCfg)
    storage: StorageCfg = field(default_factory=StorageCfg)
    warnings: list[str] = field(default_factory=list, repr=False, compare=False)

    # -- conversion ---------------------------------------------------------
    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("warnings", None)
        if redact:
            for dotted in SECRET_KEYS:
                section, key = dotted.split(".")
                if data[section].get(key):
                    data[section][key] = "<redacted>"
        return data

    @classmethod
    def from_dict(cls, data: Any) -> Config:
        cfg = cls()
        if not isinstance(data, dict):
            cfg.warnings.append("config root is not an object; using defaults")
            return cfg
        for name, value in data.items():
            if name == "version":
                continue
            section = getattr(cfg, name, None) if name != "warnings" else None
            if not dataclasses.is_dataclass(section):
                cfg.warnings.append(f"unknown section ignored: {name}")
                continue
            if not isinstance(value, dict):
                cfg.warnings.append(f"section {name} is not an object; using defaults")
                continue
            for key, raw in value.items():
                if not hasattr(section, key):
                    cfg.warnings.append(f"unknown key ignored: {name}.{key}")
                    continue
                try:
                    setattr(section, key, _coerce(raw, getattr(section, key)))
                except ValueError as exc:
                    cfg.warnings.append(f"{name}.{key}: {exc}; using default")
        cfg.validate()
        return cfg

    def validate(self) -> None:
        """Clamp out-of-range values and note what was changed."""

        def floor(section: Any, key: str, minimum: float) -> None:
            if getattr(section, key) < minimum:
                self.warnings.append(f"{type(section).__name__}.{key} raised to {minimum}")
                setattr(section, key, type(getattr(section, key))(minimum))

        floor(self.files, "settle_seconds", 0.05)
        floor(self.files, "max_settle_seconds", self.files.settle_seconds)
        floor(self.files, "poll_interval", 0.2)
        floor(self.files, "rescan_interval", 5.0)
        floor(self.files, "burst_threshold", 5)
        floor(self.autoruns, "interval", 0.5)
        floor(self.settings, "interval", 0.5)
        floor(self.processes, "interval", 0.1)
        floor(self.network, "interval", 0.5)
        floor(self.detection, "max_scan_mb", 1)
        floor(self.detection, "max_hash_mb", 1)
        floor(self.storage, "max_events", 1000)
        if self.files.backend not in ("auto", "watchdog", "polling"):
            self.warnings.append("files.backend must be auto, watchdog or polling; using auto")
            self.files.backend = "auto"
        if self.alerts.color not in ("auto", "always", "never"):
            self.alerts.color = "auto"
        for section, key, allow_empty in (
            (self.general, "min_severity", False),
            (self.alerts, "desktop_min_severity", False),
            (self.alerts, "webhook_min_severity", False),
            (self.export, "min_severity", False),
            (self.response, "quarantine_min_severity", True),
            (self.response, "kill_min_severity", True),
        ):
            value = getattr(section, key)
            if allow_empty and value == "":
                continue
            try:
                setattr(section, key, Severity.parse(value).label)
            except ValueError:
                default = getattr(type(section)(), key)
                self.warnings.append(f"{key}: {value!r} is not a severity; using {default!r}")
                setattr(section, key, default)
        valid_formats = {"json", "jsonl", "csv", "html", "zip"}
        bad = [f for f in self.export.formats if f not in valid_formats]
        if bad:
            self.warnings.append(f"export.formats: unknown {bad} ignored")
            self.export.formats = [f for f in self.export.formats if f in valid_formats] or ["html", "json"]

    # -- dotted access ------------------------------------------------------
    def get(self, dotted: str) -> Any:
        section, key = self._resolve(dotted)
        return getattr(section, key)

    def set(self, dotted: str, value: Any) -> None:
        """Set ``section.key``. Strings are parsed as JSON where possible ("true", "3", '["a"]')."""
        section, key = self._resolve(dotted)
        current = getattr(section, key)
        if isinstance(value, str) and not isinstance(current, str):
            try:
                value = json.loads(value)
            except ValueError:
                if isinstance(current, list):
                    value = [part.strip() for part in value.split(",") if part.strip()]
        setattr(section, key, _coerce(value, current))
        self.validate()

    def _resolve(self, dotted: str) -> tuple[Any, str]:
        parts = dotted.split(".")
        if len(parts) != 2:
            raise KeyError(f"use section.key, for example files.settle_seconds (got {dotted!r})")
        section = getattr(self, parts[0], None)
        if not dataclasses.is_dataclass(section) or not hasattr(section, parts[1]):
            raise KeyError(f"no such setting: {dotted}")
        return section, parts[1]

    def keys(self) -> list[str]:
        out = []
        for f in dataclasses.fields(self):
            section = getattr(self, f.name)
            if dataclasses.is_dataclass(section):
                out.extend(f"{f.name}.{k.name}" for k in dataclasses.fields(section))
        return out


def _coerce(value: Any, current: Any) -> Any:
    """Convert ``value`` to the type of the default ``current`` or raise ValueError."""
    if isinstance(current, bool):
        if isinstance(value, bool):
            return value
        raise ValueError("expected true or false")
    if isinstance(current, int):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
            raise ValueError("expected a whole number")
        return int(value)
    if isinstance(current, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("expected a number")
        return float(value)
    if isinstance(current, str):
        if not isinstance(value, str):
            raise ValueError("expected text")
        return value
    if isinstance(current, list):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError("expected a list of text values")
        return list(value)
    raise ValueError("unsupported setting type")


def config_path(data_dir: Path) -> Path:
    return Path(data_dir) / "config.json"


def load_config(path: Path | str) -> Config:
    """Load a config file; a missing or broken file yields defaults plus a warning."""
    path = Path(path)
    if not path.exists():
        return Config()
    try:
        with open(path, encoding="utf-8") as handle:
            return Config.from_dict(json.load(handle))
    except (OSError, ValueError) as exc:
        cfg = Config()
        cfg.warnings.append(f"could not read {path}: {exc}; using defaults")
        return cfg


def save_config(cfg: Config, path: Path | str, redact: bool = False) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(cfg.to_dict(redact=redact), handle, indent=2)
        handle.write("\n")
    os.replace(tmp, path)
