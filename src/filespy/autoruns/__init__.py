"""Autostart (persistence) entries: the data model, scoring, and per-OS providers."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from filespy.context import Context
from filespy.events import Indicator, Severity
from filespy.paths import classify_location
from filespy.procrules import command_indicators


@dataclass
class AutorunEntry:
    category: str  # run_key, startup_folder, scheduled_task, service, cron, systemd, launchd, ...
    location: str  # registry key or file the entry lives in
    name: str  # value name, task name, file name or a short form of the line
    command: str  # what gets run
    target: str = ""  # the program or script it launches, when that could be worked out
    content: str = ""  # whole-file entries only (shell startup files); used to show added lines
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return self.category, self.location.lower(), self.name.lower()

    def to_dict(self) -> dict[str, Any]:
        data = {"category": self.category, "location": self.location, "name": self.name,
                "command": self.command, "target": self.target}
        data.update(self.extra)
        return data


class AutorunProvider(Protocol):
    name: str
    slow: bool  # expensive providers are polled less often

    def collect(self) -> list[AutorunEntry]: ...


#: category -> (base score for a new entry, plain-English label, MITRE ATT&CK technique)
CATEGORIES: dict[str, tuple[int, str, str]] = {
    "run_key": (45, "registry Run entry", "T1547.001"),
    "startup_folder": (45, "Startup folder item", "T1547.001"),
    "scheduled_task": (45, "scheduled task", "T1053.005"),
    "service": (45, "Windows service or driver", "T1543.003"),
    "winlogon": (70, "Winlogon setting", "T1547.004"),
    "ifeo": (70, "debugger hook (Image File Execution Options)", "T1546.012"),
    "silent_exit": (70, "process-exit monitor", "T1546.012"),
    "appinit": (70, "AppInit DLL", "T1546.010"),
    "appcert": (70, "AppCert DLL", "T1546.009"),
    "boot_execute": (70, "boot-time program", "T1547.001"),
    "active_setup": (45, "Active Setup component", "T1547.014"),
    "logon_script": (55, "logon script", "T1037.001"),
    "cmd_autorun": (55, "Command Prompt AutoRun", "T1546"),
    "screensaver": (45, "screensaver program", "T1546.002"),
    "print_monitor": (70, "print monitor", "T1547.010"),
    "cron": (45, "cron job", "T1053.003"),
    "systemd": (45, "systemd unit", "T1543.002"),
    "xdg_autostart": (45, "desktop autostart entry", "T1547.013"),
    "shell_rc": (30, "shell startup file", "T1546.004"),
    "rc_local": (45, "boot script", "T1037.004"),
    "init_script": (45, "init script", "T1037.004"),
    "ld_preload": (70, "system-wide library preload", "T1574.006"),
    "ssh_key": (50, "SSH authorized key", "T1098.004"),
    "launchd": (45, "launch agent or daemon", "T1543.001"),
    "login_hook": (70, "login hook", "T1037.002"),
    "periodic": (45, "periodic script", "T1053.003"),
}
_SCRIPT_HOST = re.compile(
    r"(?:^|[\\/\s\"'])(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|"
    r"curl|wget|osascript|base64|nc|ncat|socat)(?:\.exe)?(?=[\s\"']|$)|\bcmd(?:\.exe)?\"?\s+/c\b|\b(?:ba|z)?sh\s+-c\b|"
    r"\bpython[\d.]*\s+-c\b",
    re.IGNORECASE,
)
_IMAGE_FINDINGS = ("file.rule.", "file.hash_blocklist", "file.packed", "file.type_mismatch", "file.system_name",
                   "file.yara.", "file.virustotal", "file.double_extension", "file.name_bidi")


def label(category: str) -> str:
    return CATEGORIES.get(category, (45, category.replace("_", " "), ""))[1]


def score_entry(entry: AutorunEntry, ctx: Context, action: str = "added", added_text: str = "", deep: bool = True) -> list[Indicator]:
    """Why a new or changed autostart entry deserves attention.

    With ``deep`` off (used when auditing hundreds of existing entries) only targets in
    temporary or user-writable folders are opened and examined.
    """
    base, text, mitre = CATEGORIES.get(entry.category, (45, entry.category.replace("_", " "), ""))
    verb = "was added" if action == "added" else "was changed"
    out = [Indicator(f"autorun.{entry.category}", base, f"A {text} {verb}; it runs automatically", mitre)]
    command = added_text or entry.command
    if _SCRIPT_HOST.search(command[:4000]):
        out.append(Indicator("autorun.script_host", 20, "It launches a script host or download tool rather than a normal program", "T1059"))
    out.extend(command_indicators(command, ctx.platform))
    target = entry.target
    if target:
        location = classify_location(target, ctx.platform)
        if location == "temp":
            out.append(Indicator("autorun.target_in_temp", 30, "The program it starts lives in a temporary folder", "T1547"))
        elif location == "user_writable":
            out.append(Indicator("autorun.target_user_writable", 20, "The program it starts lives in a user-writable folder", "T1547"))
        drop = ctx.state.lookup_drop(target)
        if drop is not None:
            floor = Severity.CRITICAL if drop.score >= 90 else None
            out.append(Indicator("autorun.target_dropped", 40 if drop.score >= 40 else 30,
                                 "The program it starts is a file that was dropped while FileSpy was watching", "T1547", floor))
        wanted = location != "system" if deep else location in ("temp", "user_writable", "startup")
        if ctx.analyzer is not None and wanted and os.path.isfile(target):
            report = ctx.analyzer.analyze(target)
            out.extend(i for i in report.indicators if i.id.startswith(_IMAGE_FINDINGS))
    return out


def get_providers(ctx: Context) -> list[AutorunProvider]:
    """The providers that apply to this operating system."""
    if ctx.platform == "win32":
        from filespy.autoruns import windows

        return windows.providers(ctx)
    from filespy.autoruns import posix

    return posix.providers(ctx)
