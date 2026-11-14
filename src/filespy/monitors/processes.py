"""Runtime detection: notices every new process and scores it."""

from __future__ import annotations

import os
from collections import OrderedDict

from filespy import sanitize
from filespy.events import Indicator, Severity, summarize
from filespy.monitors.base import Monitor
from filespy.paths import basename, classify_location
from filespy.procrules import ProcInfo, evaluate

try:
    import psutil
except ImportError:  # pragma: no cover - exercised only without the dependency
    psutil = None  # type: ignore[assignment]

#: File findings worth repeating on the process that runs the file.
_DROP_IDS = ("proc.dropped_file_executed", "proc.dropped_script_executed")
_IMAGE_FINDINGS = ("file.rule.", "file.hash_blocklist", "file.packed", "file.type_mismatch", "file.yara.", "file.virustotal")


def snapshot(pid: int) -> ProcInfo | None:
    """Collect what we can about a process; None if it is already gone."""
    try:
        proc = psutil.Process(pid)
        data = proc.as_dict(attrs=["name", "exe", "cmdline", "ppid", "username", "create_time"], ad_value=None)
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ProcessLookupError):
        return None
    except (psutil.AccessDenied, OSError):
        return ProcInfo(pid=pid)
    info = ProcInfo(
        pid=pid,
        name=data.get("name") or "",
        exe=data.get("exe") or "",
        cmdline=[str(part) for part in (data.get("cmdline") or [])][:200],
        ppid=data.get("ppid") or 0,
        username=data.get("username") or "",
        create_time=data.get("create_time") or 0.0,
    )
    if info.ppid:
        try:
            parent = psutil.Process(info.ppid)
            info.parent_name = parent.name()
            info.parent_exe = parent.exe()
        except (psutil.Error, OSError):
            pass
    return info


class ProcessMonitor(Monitor):
    name = "process"

    def setup(self) -> None:
        if psutil is None:
            raise RuntimeError("psutil is not installed (pip install psutil)")
        self.interval = self.ctx.config.processes.interval
        self._ignore = {name.lower() for name in self.ctx.config.processes.ignore_names}
        self._known: set[int] = set(psutil.pids())
        self._runs: OrderedDict[tuple, None] = OrderedDict()

    def poll(self) -> None:
        current = set(psutil.pids())
        for pid in sorted(current - self._known):
            if self.stopping:
                return
            self._inspect(pid)
        for pid in self._known - current:
            self.ctx.state.unflag(pid)
        self._known = current

    def _is_ours(self, info: ProcInfo) -> bool:
        own = self.ctx.state.own_pid
        return info.pid == own or info.ppid == own

    def _first_run(self, info: ProcInfo, indicators: list[Indicator]) -> bool:
        """True the first time this dropped program (as it is now on disk) runs in this session."""
        try:
            stamp = os.stat(info.exe).st_mtime_ns if info.exe else 0
        except OSError:
            stamp = 0
        script = any(i.id == "proc.dropped_script_executed" for i in indicators)
        key = (info.exe.lower(), stamp, tuple(info.cmdline[1:6]) if script else ())
        if key in self._runs:
            return False
        self._runs[key] = None
        while len(self._runs) > 10000:
            self._runs.popitem(last=False)
        return True

    def _inspect(self, pid: int) -> None:
        info = snapshot(pid)
        if info is None or self._is_ours(info) or info.name.lower() in self._ignore:
            return
        cfg = self.ctx.config.processes
        indicators: list[Indicator] = evaluate(info, self.ctx.platform, self.ctx.state, cfg.young_image_minutes,
                                               exclude=self.ctx.config.files.exclude)
        details = {
            "pid": info.pid, "ppid": info.ppid, "name": info.name, "exe": info.exe,
            "cmdline": info.command[:2000], "user": info.username, "parent_name": info.parent_name,
            "parent_exe": info.parent_exe, "create_time": info.create_time,
        }
        dropped = any(i.id in _DROP_IDS for i in indicators)
        location = classify_location(info.exe, self.ctx.platform) if info.exe else "other"
        if info.exe and (dropped or indicators) and location not in ("system", "program") and os.path.isfile(info.exe):
            report = self.ctx.analyzer.analyze(info.exe)
            details["sha256"] = report.sha256
            found = [i for i in report.indicators if i.id.startswith(_IMAGE_FINDINGS)]
            indicators.extend(found)
            # Only what is in the file counts here; where it lives is already scored.
            content = sum(i.score for i in found)
            if dropped and content >= 40 and not any(i.floor for i in indicators):
                floor = Severity.CRITICAL if content >= 90 else Severity.HIGH
                indicators.append(Indicator("proc.dropped_file_flagged", 0, "The dropped file itself looked suspicious when examined", "T1204.002", floor))
        if dropped and not self._first_run(info, indicators):
            # Seen running before in this session: keep a record, but do not raise the same alarm again.
            indicators = [i for i in indicators if i.id not in _DROP_IDS and i.id != "proc.dropped_file_flagged"]
            indicators.append(Indicator("proc.dropped_file_rerun", 5, "A program dropped earlier in this session was started again", "T1204.002"))
        if not indicators and not cfg.record_all:
            return
        score, severity = summarize(indicators)
        shown = sanitize.clean(info.name or basename(info.exe) or f"pid {pid}", 80)
        if dropped and any(i.id in _DROP_IDS for i in indicators):
            title = f"A dropped file was executed: {shown}"
        elif dropped:
            title = f"A dropped program was started again: {shown}"
        elif severity >= Severity.LOW:
            title = f"Suspicious program started: {shown}"
        else:
            title = f"Program started: {shown}"
        self.emit("process", "started", title, info.exe or info.name, indicators, details)
        if score >= 40 or dropped:
            reason = indicators[0].description if indicators else ""
            self.ctx.state.flag_process(pid, info.create_time, info.name, info.exe, score, reason)
