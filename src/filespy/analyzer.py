"""Static triage of one file: what it is, its hashes, and every reason it looks suspicious."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from filespy import fileinfo, sanitize
from filespy.config import DetectionCfg
from filespy.events import Indicator, Severity, merge_indicators
from filespy.paths import basename, classify_location
from filespy.rules import BUILTIN_BAD_HASHES, builtin_rules_text, load_hash_list, load_rules

log = logging.getLogger("filespy")

WINDOWS_SYSTEM_NAMES = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe",
    "taskhostw.exe", "dllhost.exe", "conhost.exe", "runtimebroker.exe", "spoolsv.exe", "wininit.exe",
    "dwm.exe", "ctfmon.exe", "sihost.exe", "fontdrvhost.exe", "rundll32.exe", "regsvr32.exe",
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "taskmgr.exe", "msiexec.exe",
})


@dataclass
class FileReport:
    path: str
    exists: bool = True
    size: int = 0
    kind: str = "unknown"
    ext: str = ""
    sha256: str = ""
    md5: str = ""
    entropy: float = 0.0
    location: str = "other"
    interesting: bool = False  # runnable or otherwise worth telling the user about
    indicators: list[Indicator] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def score(self) -> int:
        return sum(i.score for i in self.indicators)

    def to_details(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path, "size": self.size, "kind": self.kind, "sha256": self.sha256,
            "md5": self.md5, "entropy": self.entropy, "location": self.location,
        }
        data.update(self.details)
        if self.error:
            data["error"] = self.error
        return data


def name_indicators(name: str, kind: str) -> list[Indicator]:
    """Tricks in a file name that make a program look like a document."""
    out: list[Indicator] = []
    if sanitize.has_bidi_or_invisible(name):
        out.append(Indicator("file.name_bidi", 60, "The name contains invisible or text-direction characters that disguise its real extension", "T1036.002"))
    parts = name.rstrip(". ").lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    if len(parts) >= 3 and parts[-2].strip() in fileinfo.DECOY_EXTS and ext in fileinfo.RISKY_EXTS:
        out.append(Indicator("file.double_extension", 45, f"Double extension: looks like .{parts[-2].strip()} but is really .{ext}", "T1036.007"))
    stem = name.rsplit(".", 1)[0] if "." in name else name
    if ext in fileinfo.RISKY_EXTS and (stem.endswith("   ") or "     " in stem):
        out.append(Indicator("file.name_padding", 35, "A long run of spaces pushes the real extension out of view", "T1036.006"))
    if name != name.rstrip(". ") and kind in fileinfo.NATIVE_KINDS:
        out.append(Indicator("file.name_trailing", 20, "The name ends in a dot or space", "T1036.006"))
    return out


class FileAnalyzer:
    """Thread-safe. ``analyze`` never raises; problems are reported in ``FileReport.error``."""

    def __init__(self, cfg: DetectionCfg | None = None, platform: str | None = None) -> None:
        self.cfg = cfg or DetectionCfg()
        self.platform = platform or sys.platform
        self.rules = load_rules(self.cfg.rules_files)
        self.bad_hashes = dict(BUILTIN_BAD_HASHES)
        self.bad_hashes.update(load_hash_list(self.cfg.hash_blocklists))
        self.good_hashes = load_hash_list(self.cfg.hash_allowlists)
        # Never flag our own rule file (it necessarily contains every signature string).
        self._self_hashes = {hashlib.sha256(builtin_rules_text().encode("utf-8")).hexdigest()}
        self._cache: OrderedDict[tuple[str, int, int], FileReport] = OrderedDict()
        self._lock = threading.Lock()
        self._yara = self._load_yara()
        self._vt_cache: dict[str, int] = {}
        self._vt_last = 0.0

    # -- optional engines -----------------------------------------------------
    def _load_yara(self) -> Any:
        if not self.cfg.yara_rules_dir:
            return None
        try:
            import yara  # type: ignore[import-not-found]

            files = {
                f"r{n}": os.path.join(self.cfg.yara_rules_dir, name)
                for n, name in enumerate(sorted(os.listdir(self.cfg.yara_rules_dir)))
                if name.lower().endswith((".yar", ".yara"))
            }
            return yara.compile(filepaths=files) if files else None
        except Exception as exc:  # noqa: BLE001 - optional feature must not stop the tool
            log.warning("YARA rules not loaded: %s", exc)
            return None

    def _virustotal(self, sha256: str) -> int | None:
        """Number of engines calling this hash malicious, or None. Sends the hash only."""
        key = self.cfg.virustotal_api_key or os.environ.get("FILESPY_VT_KEY", "")
        if not (self.cfg.virustotal and key and sha256):
            return None
        with self._lock:
            if sha256 in self._vt_cache:
                return self._vt_cache[sha256]
            if time.time() - self._vt_last < 16:  # free tier: 4 lookups a minute
                return None
            self._vt_last = time.time()
        request = urllib.request.Request(  # noqa: S310 - fixed https URL
            f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:  # noqa: S310
                stats = json.load(response)["data"]["attributes"]["last_analysis_stats"]
                count = int(stats.get("malicious", 0))
        except urllib.error.HTTPError as exc:
            count = 0 if exc.code == 404 else -1
        except Exception:  # noqa: BLE001 - network trouble is not an analysis failure
            count = -1
        if count >= 0:
            with self._lock:
                self._vt_cache[sha256] = count
            return count
        return None

    # -- main entry point -----------------------------------------------------
    def analyze(self, path: str) -> FileReport:
        report = FileReport(path=path, ext=fileinfo.extension(path), location=classify_location(path, self.platform))
        try:
            info = os.lstat(path)
        except OSError as exc:
            report.exists = False
            report.error = f"cannot stat: {exc.strerror or exc}"
            return report
        if not stat.S_ISREG(info.st_mode):
            report.kind = "link" if stat.S_ISLNK(info.st_mode) else "special"
            return report
        key = (path, info.st_size, info.st_mtime_ns)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        report.size = info.st_size
        try:
            self._inspect(report, info)
        except OSError as exc:
            report.error = f"cannot read: {exc.strerror or exc}"
        except Exception as exc:  # noqa: BLE001 - a hostile file must never crash the monitor
            log.exception("analysis failed for %r", path)
            report.error = f"analysis error: {type(exc).__name__}"
        report.indicators = merge_indicators(report.indicators)
        if not report.error:
            with self._lock:
                self._cache[key] = report
                while len(self._cache) > 512:
                    self._cache.popitem(last=False)
        return report

    def _inspect(self, report: FileReport, info: os.stat_result) -> None:
        cfg, name = self.cfg, basename(report.path)
        ext, loc = report.ext, report.location
        with fileinfo.open_regular(report.path) as handle:
            head = handle.read(4096)
            kind = report.kind = fileinfo.detect_kind(head, name)
            runnable = (
                kind in fileinfo.RUNNABLE_KINDS
                or ext in fileinfo.RISKY_EXTS
                or (kind == "ole" and ext in ("msi", "msp", "mst", ""))
            )
            # Programs and scripts are read in full (up to the limit); other files only get a quick look.
            limit = cfg.max_scan_mb * 1024 * 1024 if runnable else min(cfg.max_scan_mb, 1) * 1024 * 1024
            data = head + handle.read(max(0, limit - len(head)))
            hash_limit = cfg.max_hash_mb * 1024 * 1024 if runnable else min(cfg.max_hash_mb, 16) * 1024 * 1024
            if report.size <= hash_limit:
                handle.seek(0)
                report.sha256, report.md5, _ = fileinfo.hash_stream(handle, hash_limit)
        report.entropy = round(fileinfo.shannon_entropy(data[: 4 * 1024 * 1024]), 2)
        report.interesting = runnable or ext in fileinfo.CONTAINER_EXTS
        ind = report.indicators
        pe = fileinfo.parse_pe(data, report.size) if kind == "pe" else None

        if report.sha256 and (report.sha256 in self.good_hashes or report.sha256 in self._self_hashes):
            report.details["allowlisted"] = True
            return
        bad = self.bad_hashes.get(report.sha256) or self.bad_hashes.get(report.md5)
        if bad:
            ind.append(Indicator("file.hash_blocklist", 100, f"Known-bad file: {bad}", "T1204.002", Severity.CRITICAL))

        ind.extend(self.rules.match(data, kind))
        ind.extend(name_indicators(name, kind))

        native = kind in fileinfo.NATIVE_KINDS
        # A library, or a program that at least carries a signature, is common during normal installs.
        calm = pe is not None and (pe.is_dll or pe.signed)
        clickable = kind == "script" and (ext in fileinfo.CLICKABLE_SCRIPT_EXTS or (os.name != "nt" and info.st_mode & 0o111))
        if native and loc == "startup":
            ind.append(Indicator("file.program_in_startup", 70, "A program was placed in a location that runs automatically at login", "T1547.001"))
        elif runnable and loc == "startup":
            ind.append(Indicator("file.runnable_in_startup", 55, "A script or shortcut was placed in a location that runs automatically at login", "T1547.001"))
        elif native and loc == "temp":
            ind.append(Indicator("file.program_in_temp", 25 if calm else 40, "A program was written to a temporary folder", "T1105"))
        elif native and loc == "user_writable":
            ind.append(Indicator("file.program_in_user_dir", 25 if calm else 40, "A program was written to a user-writable folder", "T1105"))
        elif clickable and loc in ("temp", "user_writable"):
            ind.append(Indicator("file.script_dropped", 20, "A script that runs when opened was written to a user-writable folder", "T1105"))
        if native and ext in fileinfo.DECOY_EXTS:
            ind.append(Indicator("file.type_mismatch", 45, f"This is a program but it is named like a .{ext} file", "T1036.008"))
        elif native and ext and ext not in fileinfo.NATIVE_EXTS and ext != "tmp" and self.platform == "win32":
            ind.append(Indicator("file.odd_extension", 15, f"This is a program with an unusual extension (.{ext})", "T1036.008"))
        if kind == "pe" and name.lower() in WINDOWS_SYSTEM_NAMES and loc != "system":
            ind.append(Indicator("file.system_name", 50, f"Uses the name of a Windows system program ({name}) outside the Windows folder", "T1036.005"))
        if runnable and fileinfo.is_hidden(report.path, info) and loc in ("temp", "user_writable", "startup"):
            ind.append(Indicator("file.hidden", 15, "The file is hidden", "T1564.001"))
        if native and os.name != "nt" and info.st_mode & stat.S_ISUID:
            ind.append(Indicator("file.setuid", 45, "The program runs with its owner's privileges (setuid)", "T1548.001"))

        if pe is not None:
            report.details["pe"] = {
                "dll": pe.is_dll, "dotnet": pe.is_dotnet, "x64": pe.is_64bit, "signature_present": pe.signed,
                "sections": [s[0] for s in pe.sections][:16], "max_section_entropy": pe.max_entropy,
            }
            if pe.packer:
                ind.append(Indicator("file.packed", 25, f"Packed with {pe.packer}, which hides the real code", "T1027.002"))
            elif pe.max_entropy >= cfg.entropy_threshold:
                ind.append(Indicator("file.high_entropy", 20, f"Contains encrypted or compressed code (entropy {pe.max_entropy})", "T1027.002"))
            if pe.writable_code:
                ind.append(Indicator("file.writable_code", 10, "Has a code section that can rewrite itself", "T1027"))
            if not pe.signed and not pe.is_dll and loc in ("temp", "user_writable", "startup"):
                ind.append(Indicator("file.unsigned", 10, "Carries no digital signature", ""))
        zone = fileinfo.read_zone_identifier(report.path)
        if zone:
            report.details["zone"] = zone
            if runnable and zone.get("ZoneId") in ("3", "4"):
                ind.append(Indicator("file.from_internet", 10, "Downloaded from the internet", "T1105"))

        if self._yara is not None and runnable:
            try:
                for match in self._yara.match(data=data, timeout=10)[:10]:
                    ind.append(Indicator(f"file.yara.{match.rule}", 70, f"Matches YARA rule {match.rule}", ""))
            except Exception as exc:  # noqa: BLE001
                log.debug("yara match failed: %s", exc)
        if runnable and ind:
            hits = self._virustotal(report.sha256)
            if hits is not None:
                report.details["virustotal_malicious"] = hits
                if hits >= 5:
                    ind.append(Indicator("file.virustotal", 100, f"{hits} antivirus engines on VirusTotal call this file malicious", "", Severity.CRITICAL))
                elif hits >= 1:
                    ind.append(Indicator("file.virustotal_few", 40, f"{hits} antivirus engine(s) on VirusTotal flag this file", ""))
