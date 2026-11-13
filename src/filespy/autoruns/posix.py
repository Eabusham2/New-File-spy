"""Linux and macOS autostart locations: cron, systemd, desktop autostart, shell startup
files, library preloads, SSH keys and launchd."""

from __future__ import annotations

import base64
import hashlib
import os
import plistlib
import re
import shlex

from filespy.autoruns import AutorunEntry
from filespy.autoruns.cmdline import extract_posix_target
from filespy.context import Context
from filespy.textutil import wait_until_quiet

MAX_FILE = 262144
_CRON_AT = re.compile(r"^@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)\s+(.*)$")
_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_KEY_TYPES = re.compile(r"^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)$")


def read_text(path: str, limit: int = MAX_FILE) -> str | None:
    """Text of a regular file (links are followed, as the system itself would); None if unreadable."""
    try:
        if not os.path.isfile(path):
            return None
        wait_until_quiet(path)
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def list_files(folder: str, suffixes: tuple[str, ...] = ()) -> list[str]:
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    paths = [os.path.join(folder, n) for n in names[:2000] if not suffixes or n.endswith(suffixes)]
    return [p for p in paths if os.path.isfile(p)]


def parse_cron_line(line: str, has_user: bool) -> str | None:
    """The command of one crontab line, or None for comments, blanks and variable assignments."""
    text = line.strip()
    if not text or text.startswith("#") or _ENV_LINE.match(text):
        return None
    match = _CRON_AT.match(text)
    if match:
        rest = match.group(1)
    else:
        parts = text.split(None, 5)
        if len(parts) < 6:
            return None
        rest = parts[5]
    if has_user:
        parts = rest.split(None, 1)
        if len(parts) < 2:
            return None
        rest = parts[1]
    return rest.strip() or None


def parse_unit(text: str) -> list[str]:
    """Commands from the Exec lines of a systemd unit (start-up ones only)."""
    commands = []
    joined = text.replace("\\\n", " ")
    for line in joined.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.strip() in ("ExecStart", "ExecStartPre", "ExecStartPost"):
            value = value.strip().lstrip("-@+!:").strip()
            if value:
                commands.append(value)
    return commands


def parse_desktop_exec(text: str) -> tuple[str, bool]:
    """(command, hidden) from a .desktop file, with %f-style field codes removed."""
    command, hidden, in_entry = "", False, False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            in_entry = line == "[Desktop Entry]"
        elif in_entry and line.startswith("Exec="):
            command = re.sub(r"\s%[a-zA-Z]", "", line[5:]).strip()
        elif in_entry and line.lower().replace(" ", "") == "hidden=true":
            hidden = True
    return command, hidden


def parse_authorized_keys(text: str) -> list[tuple[str, str]]:
    """(identity, options) per key. The identity is the key type, a fingerprint and the comment."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        index = next((i for i, token in enumerate(tokens) if _KEY_TYPES.match(token)), None)
        if index is None or index + 1 >= len(tokens):
            continue
        blob = tokens[index + 1]
        try:
            digest = hashlib.sha256(base64.b64decode(blob + "=" * (-len(blob) % 4))).hexdigest()[:16]
        except ValueError:
            digest = hashlib.sha256(blob.encode()).hexdigest()[:16]
        comment = " ".join(tokens[index + 2:])[:80]
        raw_options = line.split(tokens[index], 1)[0].strip()
        out.append((f"{tokens[index]} SHA256:{digest} {comment}".strip(), raw_options))
    return out


class CronProvider:
    name = "cron"
    slow = False

    def __init__(self, system_files: list[str], system_dirs: list[str], user_dirs: list[str], script_dirs: list[str]) -> None:
        self.system_files, self.system_dirs = system_files, system_dirs
        self.user_dirs, self.script_dirs = user_dirs, script_dirs

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        tables = [(p, True) for p in self.system_files]
        tables += [(p, True) for d in self.system_dirs for p in list_files(d)]
        tables += [(p, False) for d in self.user_dirs for p in list_files(d)]
        for path, has_user in tables:
            for line in (read_text(path) or "").splitlines():
                command = parse_cron_line(line, has_user)
                if command:
                    out.append(AutorunEntry("cron", path, command[:120], command, extract_posix_target(command)))
        for folder in self.script_dirs:
            for path in list_files(folder):
                if not os.path.basename(path).startswith("."):
                    out.append(AutorunEntry("periodic" if "periodic" in folder else "cron", folder, os.path.basename(path), path, path))
        return out


class SystemdProvider:
    name = "systemd"
    slow = False

    def __init__(self, folders: list[str]) -> None:
        self.folders = list(dict.fromkeys(os.path.realpath(f) for f in folders))
        self._cache: dict[str, tuple[tuple[int, int], AutorunEntry]] = {}

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        seen: set[str] = set()
        for folder in self.folders:
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries[:5000]:
                if not entry.name.endswith((".service", ".timer")):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                signature = (info.st_size, info.st_mtime_ns)
                seen.add(entry.path)
                cached = self._cache.get(entry.path)
                if cached is None or cached[0] != signature:
                    commands = parse_unit(read_text(entry.path) or "")
                    command = " ; ".join(commands) or "(no start command)"
                    target = extract_posix_target(commands[0]) if commands else ""
                    cached = (signature, AutorunEntry("systemd", folder, entry.name, command, target))
                    self._cache[entry.path] = cached
                out.append(cached[1])
        for path in [p for p in self._cache if p not in seen]:
            del self._cache[path]
        return out


class FilesProvider:
    """Desktop autostart entries, whole-file startup scripts, preloads, SSH keys and init scripts."""

    name = "startup-files"
    slow = False

    def __init__(self, autostart_dirs: list[str], rc_files: list[str], rc_dirs: list[str], boot_scripts: list[str],
                 preload_files: list[str], key_files: list[str], init_dirs: list[str]) -> None:
        self.autostart_dirs, self.rc_files, self.rc_dirs = autostart_dirs, rc_files, rc_dirs
        self.boot_scripts, self.preload_files = boot_scripts, preload_files
        self.key_files, self.init_dirs = key_files, init_dirs

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        for folder in self.autostart_dirs:
            for path in list_files(folder, (".desktop",)):
                command, hidden = parse_desktop_exec(read_text(path) or "")
                if command:
                    out.append(AutorunEntry("xdg_autostart", folder, os.path.basename(path), command,
                                            extract_posix_target(command), extra={"hidden": hidden}))
        whole = [("shell_rc", p) for p in self.rc_files]
        whole += [("shell_rc", p) for d in self.rc_dirs for p in list_files(d)]
        whole += [("rc_local", p) for p in self.boot_scripts]
        for category, path in whole:
            text = read_text(path)
            if text is not None:
                digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
                out.append(AutorunEntry(category, os.path.dirname(path), os.path.basename(path), f"contents {digest}", path, content=text))
        for path in self.preload_files:
            for line in (read_text(path) or "").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(AutorunEntry("ld_preload", path, line, line, line))
        for path in self.key_files:
            for identity, options in parse_authorized_keys(read_text(path) or ""):
                out.append(AutorunEntry("ssh_key", path, identity, options or "(no restrictions)"))
        for folder in self.init_dirs:
            for path in list_files(folder):
                out.append(AutorunEntry("init_script", folder, os.path.basename(path), path, path))
        return out


class LaunchdProvider:
    name = "launchd"
    slow = False

    def __init__(self, folders: list[str], loginwindow_plist: str = "/Library/Preferences/com.apple.loginwindow.plist") -> None:
        self.folders = folders
        self.loginwindow_plist = loginwindow_plist

    @staticmethod
    def _load(path: str) -> dict | None:
        try:
            if os.path.getsize(path) > 1024 * 1024:
                return None
            with open(path, "rb") as handle:
                data = plistlib.load(handle)
            return data if isinstance(data, dict) else None
        except Exception:  # noqa: BLE001 - malformed plists come in many shapes
            return None

    def collect(self) -> list[AutorunEntry]:
        out: list[AutorunEntry] = []
        for folder in self.folders:
            for path in list_files(folder, (".plist",)):
                data = self._load(path)
                if data is None:
                    out.append(AutorunEntry("launchd", folder, os.path.basename(path), "(unreadable plist)", ""))
                    continue
                arguments = data.get("ProgramArguments")
                program = data.get("Program")
                if isinstance(arguments, list) and arguments:
                    command = " ".join(shlex.quote(str(a)) for a in arguments[:50])
                    target = extract_posix_target(command)
                else:
                    command = target = str(program or "")
                if isinstance(program, str) and program:
                    target = program
                extra = {"label": str(data.get("Label", "")), "run_at_load": bool(data.get("RunAtLoad", False))}
                out.append(AutorunEntry("launchd", folder, os.path.basename(path), command or "(no program)", target, extra=extra))
        hooks = self._load(self.loginwindow_plist) or {}
        for key in ("LoginHook", "LogoutHook"):
            if isinstance(hooks.get(key), str) and hooks[key]:
                out.append(AutorunEntry("login_hook", self.loginwindow_plist, key, hooks[key], extract_posix_target(hooks[key])))
        return out


def _home_files(home: str, names: tuple[str, ...]) -> list[str]:
    return [os.path.join(home, name) for name in names]


SHELL_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
               ".config/fish/config.fish")


def providers(ctx: Context) -> list:
    home = os.path.expanduser("~")
    keys = _home_files(home, (".ssh/authorized_keys", ".ssh/authorized_keys2"))
    rc_files = _home_files(home, SHELL_FILES)
    if ctx.platform == "darwin":
        return [
            LaunchdProvider([os.path.join(home, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]),
            CronProvider(["/etc/crontab"], [], ["/usr/lib/cron/tabs", "/var/at/tabs"],
                         ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]),
            FilesProvider([], rc_files + ["/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/bashrc"], [], ["/etc/rc.common"],
                          [], keys, []),
        ]
    return [
        CronProvider(["/etc/crontab"], ["/etc/cron.d"], ["/var/spool/cron/crontabs", "/var/spool/cron"],
                     ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]),
        SystemdProvider(["/etc/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
                         "/lib/systemd/system", "/etc/systemd/user", os.path.join(home, ".config/systemd/user")]),
        FilesProvider(
            [os.path.join(home, ".config/autostart"), "/etc/xdg/autostart"],
            rc_files + ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc", "/etc/environment"],
            ["/etc/profile.d"], ["/etc/rc.local"], ["/etc/ld.so.preload"], keys, ["/etc/init.d"],
        ),
    ]
