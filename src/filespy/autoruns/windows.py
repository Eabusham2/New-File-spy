"""Windows autostart locations, read through a RegistryBackend so they can be tested anywhere."""

from __future__ import annotations

import os
import re
import struct
import uuid
from typing import Any

from filespy.autoruns import AutorunEntry
from filespy.autoruns.cmdline import extract_target, normalise_service_path
from filespy.context import Context
from filespy.paths import basename, classify_location
from filespy.registry import RegistryBackend, _lookup

CV = r"Software\Microsoft\Windows\CurrentVersion"
CV32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion"
NT = r"Software\Microsoft\Windows NT\CurrentVersion"
NT32 = r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion"

#: Keys where every value is one autostart command.
RUN_KEYS: tuple[tuple[str, str], ...] = tuple(
    (hive, key)
    for hive in ("HKCU", "HKLM")
    for key in (
        CV + r"\Run", CV + r"\RunOnce", CV + r"\RunServices", CV + r"\RunServicesOnce",
        CV + r"\Policies\Explorer\Run", CV32 + r"\Run", CV32 + r"\RunOnce",
    )
)
#: (category, hive, key, value name) - single values that name a program.
NAMED_VALUES: tuple[tuple[str, str, str, str], ...] = (
    ("winlogon", "HKLM", NT + r"\Winlogon", "Shell"),
    ("winlogon", "HKLM", NT + r"\Winlogon", "Userinit"),
    ("winlogon", "HKLM", NT + r"\Winlogon", "Taskman"),
    ("winlogon", "HKLM", NT + r"\Winlogon", "AppSetup"),
    ("winlogon", "HKCU", NT + r"\Winlogon", "Shell"),
    ("run_key", "HKCU", NT + r"\Windows", "Load"),
    ("run_key", "HKCU", NT + r"\Windows", "Run"),
    ("appinit", "HKLM", NT + r"\Windows", "AppInit_DLLs"),
    ("appinit", "HKLM", NT32 + r"\Windows", "AppInit_DLLs"),
    ("boot_execute", "HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute"),
    ("logon_script", "HKCU", "Environment", "UserInitMprLogonScript"),
    ("cmd_autorun", "HKCU", r"Software\Microsoft\Command Processor", "AutoRun"),
    ("cmd_autorun", "HKLM", r"Software\Microsoft\Command Processor", "AutoRun"),
    ("screensaver", "HKCU", r"Control Panel\Desktop", "SCRNSAVE.EXE"),
)
#: (category, hive, key) - keys where every value is a library to load.
VALUE_MAPS: tuple[tuple[str, str, str], ...] = (
    ("appcert", "HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"),
)
#: (category, hive, parent key, value name) - one entry per subkey that has the value.
SUBKEY_VALUES: tuple[tuple[str, str, str, str], ...] = (
    ("ifeo", "HKLM", NT + r"\Image File Execution Options", "Debugger"),
    ("ifeo", "HKLM", NT32 + r"\Image File Execution Options", "Debugger"),
    ("silent_exit", "HKLM", NT + r"\SilentProcessExit", "MonitorProcess"),
    ("active_setup", "HKLM", r"Software\Microsoft\Active Setup\Installed Components", "StubPath"),
    ("active_setup", "HKCU", r"Software\Microsoft\Active Setup\Installed Components", "StubPath"),
    ("print_monitor", "HKLM", r"SYSTEM\CurrentControlSet\Control\Print\Monitors", "Driver"),
)
SERVICES = r"SYSTEM\CurrentControlSet\Services"
TASK_TREE = NT + r"\Schedule\TaskCache\Tree"
TASK_TASKS = NT + r"\Schedule\TaskCache\Tasks"


PROFILE_LIST = NT + r"\ProfileList"
_USER_SID = re.compile(r"^S-1-(?:5-21|12-1)-[\d-]+$")
_STARTUP_TAIL = r"Microsoft\Windows\Start Menu\Programs\Startup"
#: Values that hold several programs, and the separator between them.
_LIST_VALUES = {"userinit": r"\s*,\s*", "shell": r"\s*,\s*", "taskman": r"\s*,\s*", "appinit_dlls": r"[\s,]+",
                "bootexecute": r"\s*\|\s*"}
_EXPECTED = frozenset({"explorer.exe", "userinit.exe", "autocheck"})


def user_hives(registry: RegistryBackend) -> list[tuple[str, str, str]]:
    """(hive, key prefix, label) for every user whose registry is loaded.

    When FileSpy runs elevated under another account, HKCU is not the logged-on user's
    hive, so per-user locations are read under HKEY_USERS for each real user instead.
    """
    sids = [sid for sid in (registry.subkeys("HKU", "") or []) if _USER_SID.match(sid)]
    if not sids:
        return [("HKCU", "", "HKCU")]
    return [("HKU", sid + "\\", f"HKU\\{sid}") for sid in sids]


def _text(data: Any) -> str:
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, list):
        return " | ".join(str(item) for item in data if str(item).strip())
    return ""


def parse_lnk(data: bytes) -> tuple[str, str]:
    """(target path, arguments) of a Windows shortcut; empty strings if it cannot be parsed."""
    try:
        if len(data) < 76 or data[:4] != b"L\x00\x00\x00":
            return "", ""
        flags = struct.unpack_from("<I", data, 20)[0]
        offset = 76
        if flags & 0x1:  # item ID list
            offset += 2 + struct.unpack_from("<H", data, offset)[0]
        target = ""
        if flags & 0x2:  # link info
            start = offset
            size, header, info_flags, _vol, local_base, _net, suffix = struct.unpack_from("<7I", data, start)
            if info_flags & 0x1 and local_base:
                end = data.index(b"\x00", start + local_base)
                target = data[start + local_base:end].decode("cp1252", "replace")
                if suffix:
                    end = data.index(b"\x00", start + suffix)
                    target += data[start + suffix:end].decode("cp1252", "replace")
                if header >= 0x24:
                    wide = struct.unpack_from("<I", data, start + 28)[0]
                    if wide:
                        chunk = data[start + wide:start + size]
                        target = chunk.decode("utf-16-le", "replace").split("\x00", 1)[0] or target
            offset = start + size
        unicode_strings = bool(flags & 0x80)
        strings: dict[str, str] = {}
        for bit, name in ((0x4, "name"), (0x8, "relative"), (0x10, "workdir"), (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                count = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                length = count * 2 if unicode_strings else count
                raw = data[offset:offset + length]
                offset += length
                strings[name] = raw.decode("utf-16-le" if unicode_strings else "cp1252", "replace")
        return target or strings.get("relative", ""), strings.get("args", "")
    except (struct.error, ValueError, IndexError):
        return "", ""


def _parse_actions(blob: bytes) -> list[str]:
    position = 2
    version = struct.unpack_from("<H", blob, 0)[0]

    def read_string() -> str:
        nonlocal position
        length = struct.unpack_from("<I", blob, position)[0]
        position += 4
        if length % 2 or length > len(blob) - position:
            raise ValueError("bad string length")
        text = blob[position:position + length].decode("utf-16-le")
        position += length
        return text

    if version >= 2:
        read_string()  # the account context ("Author", "LocalSystem", ...)
    commands: list[str] = []
    while position + 2 <= len(blob) and len(commands) < 32:
        magic = struct.unpack_from("<H", blob, position)[0]
        position += 2
        if magic == 0x6666:  # run a program
            read_string()
            path, arguments = read_string(), read_string()
            read_string()
            if version >= 3:
                position += 2
            commands.append(f"{path} {arguments}".strip())
        elif magic == 0x7777:  # COM handler
            read_string()
            clsid = uuid.UUID(bytes_le=blob[position:position + 16])
            position += 16
            commands.append(f"COM handler {{{clsid}}} {read_string()}".strip())
        else:
            break
    return commands


def parse_task_actions(blob: bytes) -> list[str]:
    """Commands of a scheduled task from its TaskCache ``Actions`` value. Never raises."""
    try:
        commands = _parse_actions(blob)
    except (struct.error, ValueError, IndexError, UnicodeDecodeError):
        commands = []
    if commands:
        return commands
    found = re.findall(r"[\x20-\x7e]{4,}", blob.decode("utf-16-le", "ignore"))
    return [" ".join(found[1:] or found)] if found else []


class RegistryRunProvider:
    """Run keys and the single-value hooks. Cheap, so polled every time."""

    name = "registry"
    slow = False

    def __init__(self, registry: RegistryBackend) -> None:
        self.reg = registry
        self._exists = os.path.isfile if os.name == "nt" else None

    def _target(self, command: str) -> str:
        return extract_target(self.reg.expand(command), exists=self._exists)

    def _places(self, hive: str, key: str) -> list[tuple[str, str, str]]:
        """(hive, key, label) to read for a catalog location; per-user ones fan out to every user."""
        if hive != "HKCU":
            return [(hive, key, f"{hive}\\{key}")]
        return [(h, prefix + key, f"{label}\\{key}") for h, prefix, label in user_hives(self.reg)]

    def _best_target(self, name: str, command: str) -> str:
        """For values that list several programs, the one that does not belong there."""
        separator = _LIST_VALUES.get(name.lower())
        items = [i for i in re.split(separator, command) if i.strip()] if separator else [command]
        targets = [t for t in (self._target(item) for item in items) if t]
        for target in targets:
            if classify_location(target, "win32") != "system" and basename(target).lower() not in _EXPECTED:
                return target
        return targets[0] if targets else ""

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        for hive, key in RUN_KEYS:
            for real_hive, real_key, label in self._places(hive, key):
                for name, data in (self.reg.values(real_hive, real_key) or {}).items():
                    command = _text(data)
                    if command:
                        out.append(AutorunEntry("run_key", label, name or "(Default)", command, self._target(command)))
        for category, hive, key, name in NAMED_VALUES:
            for real_hive, real_key, label in self._places(hive, key):
                command = _text(self.reg.get(real_hive, real_key, name))
                if command:
                    out.append(AutorunEntry(category, label, name, command, self._best_target(name, command)))
        for category, hive, key in VALUE_MAPS:
            for name, data in (self.reg.values(hive, key) or {}).items():
                command = _text(data)
                if command:
                    out.append(AutorunEntry(category, f"{hive}\\{key}", name, command, self._target(command)))
        return out


class RegistryDeepProvider:
    """Hooks that need one read per subkey, services and scheduled tasks. Polled less often."""

    name = "registry-deep"
    slow = True

    def __init__(self, registry: RegistryBackend, services: bool = True, tasks: bool = True) -> None:
        self.reg = registry
        self.services = services
        self.tasks = tasks

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        reg = self.reg
        for category, hive, parent, value in SUBKEY_VALUES:
            places = [(hive, parent, f"{hive}\\{parent}")]
            if hive == "HKCU":
                places = [(h, prefix + parent, f"{label}\\{parent}") for h, prefix, label in user_hives(reg)]
            for real_hive, real_parent, label in places:
                for sub in (reg.subkeys(real_hive, real_parent) or [])[:5000]:
                    command = _text(reg.get(real_hive, f"{real_parent}\\{sub}", value))
                    if command:
                        out.append(AutorunEntry(category, label, sub, command, extract_target(reg.expand(command))))
        if self.services:
            out.extend(self._services())
        if self.tasks:
            out.extend(self._tasks())
        return out

    def _services(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        reg = self.reg
        for name in (reg.subkeys("HKLM", SERVICES) or [])[:8000]:
            values = reg.values("HKLM", f"{SERVICES}\\{name}") or {}
            image = _text(_lookup(values, "ImagePath"))
            if not image:
                continue
            target = extract_target(reg.expand(normalise_service_path(image)))
            extra = {"start": _lookup(values, "Start"), "type": _lookup(values, "Type")}
            out.append(AutorunEntry("service", f"HKLM\\{SERVICES}", name, image, target, extra=extra))
            if "svchost" in image.lower():
                library = _text(reg.get("HKLM", f"{SERVICES}\\{name}\\Parameters", "ServiceDll"))
                if library:
                    out.append(AutorunEntry("service", f"HKLM\\{SERVICES}", f"{name} (ServiceDll)", library, reg.expand(library)))
        return out

    def _tasks(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        reg = self.reg
        stack = [("", TASK_TREE)]
        visited = 0
        while stack and visited < 4000:
            relative, key = stack.pop()
            visited += 1
            values = reg.values("HKLM", key)
            if values is None:
                continue
            task_id = _lookup(values, "Id")
            if relative and isinstance(task_id, str):
                blob = reg.get("HKLM", f"{TASK_TASKS}\\{task_id}", "Actions")
                commands = parse_task_actions(blob) if isinstance(blob, bytes) else []
                target = extract_target(reg.expand(commands[0])) if commands and not commands[0].startswith("COM handler") else ""
                out.append(AutorunEntry("scheduled_task", "Task Scheduler", relative, " ; ".join(commands), target,
                                        extra={"built_in": relative.lower().startswith("\\microsoft\\")}))
            for sub in reg.subkeys("HKLM", key) or []:
                stack.append((f"{relative}\\{sub}", f"{key}\\{sub}"))
        return out


class StartupFolderProvider:
    name = "startup-folders"
    slow = False

    def __init__(self, folders: list[str]) -> None:
        self.folders = folders

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        for folder in self.folders:
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names[:500]:
                path = os.path.join(folder, name)
                if name.lower() == "desktop.ini" or not os.path.isfile(path):
                    continue
                command, target = path, path
                if name.lower().endswith(".lnk"):
                    try:
                        with open(path, "rb") as handle:
                            link_target, arguments = parse_lnk(handle.read(65536))
                    except OSError:
                        link_target, arguments = "", ""
                    if link_target:
                        command = f"{link_target} {arguments}".strip()
                        target = extract_target(f'"{link_target}" {arguments}')
                out.append(AutorunEntry("startup_folder", folder, name, command, target))
        return out


def startup_folders(env: dict[str, str] | None = None, registry: RegistryBackend | None = None) -> list[str]:
    """Startup folders of this user, of all users, and of every user profile on the machine."""
    env = dict(os.environ) if env is None else env
    folders = []
    if env.get("APPDATA"):
        folders.append(env["APPDATA"] + "\\" + _STARTUP_TAIL)
    if env.get("PROGRAMDATA"):
        folders.append(env["PROGRAMDATA"] + "\\" + _STARTUP_TAIL)
    if registry is not None:
        for sid in registry.subkeys("HKLM", PROFILE_LIST) or []:
            if not _USER_SID.match(sid):
                continue
            profile = registry.get("HKLM", f"{PROFILE_LIST}\\{sid}", "ProfileImagePath")
            if isinstance(profile, str) and profile:
                folders.append(registry.expand(profile) + "\\AppData\\Roaming\\" + _STARTUP_TAIL)
    seen: set[str] = set()
    return [f for f in folders if not (f.lower() in seen or seen.add(f.lower()))]


def providers(ctx: Context) -> list:
    if ctx.registry is None:
        return []
    cfg = ctx.config.autoruns
    return [
        RegistryRunProvider(ctx.registry),
        StartupFolderProvider(startup_folders(registry=ctx.registry)),
        RegistryDeepProvider(ctx.registry, cfg.services, cfg.scheduled_tasks),
    ]
