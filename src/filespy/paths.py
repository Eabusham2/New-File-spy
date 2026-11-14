"""Data directory, default watch locations and path classification.

Classification works on plain strings so Windows rules can be tested on any OS.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def data_dir(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    override = env.get("FILESPY_HOME")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "FileSpy"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "FileSpy"
    base = env.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "filespy"


def ensure_private_dir(path: Path | str) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def norm(path: str | os.PathLike[str]) -> str:
    """Canonical form for comparing paths from different sources (events, process images)."""
    text = os.fspath(path)
    try:
        text = os.path.realpath(text)
    except (OSError, ValueError):
        text = os.path.abspath(text)
    return os.path.normcase(text)


def _slashed(path: str) -> str:
    return path.replace("\\", "/").lower()


def default_watch_roots(
    platform: str = sys.platform, env: Mapping[str, str] | None = None, home: str | None = None
) -> list[str]:
    """Directories malware commonly drops into. Callers skip the ones that do not exist."""
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    roots: list[str] = []
    if platform == "win32":
        sep = "\\"
        profile = env.get("USERPROFILE") or home
        system_root = env.get("SystemRoot") or env.get("SYSTEMROOT") or r"C:\Windows"
        for var in ("TEMP", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PUBLIC"):
            if env.get(var):
                roots.append(env[var])
        roots += [profile + sep + name for name in ("Downloads", "Desktop", "Documents")]
        roots += [system_root + sep + "Temp", system_root + sep + "Tasks"]
    elif platform == "darwin":
        roots += ["/private/tmp", "/private/var/tmp", "/Users/Shared"]
        roots += [home + "/" + name for name in ("Downloads", "Desktop", "Library/LaunchAgents")]
        roots += ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
    else:
        roots += ["/tmp", "/var/tmp", "/dev/shm"]
        roots += [
            home + "/" + name
            for name in ("Downloads", "Desktop", ".config/autostart", ".config/systemd/user", ".local/bin")
        ]
        roots += ["/etc/cron.d", "/etc/systemd/system"]
    seen: set[str] = set()
    unique = []
    for root in roots:
        key = _slashed(root).rstrip("/")
        if key and key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def drop_nested(roots: Iterable[str]) -> list[str]:
    """Remove roots that live inside another root (recursive watching already covers them)."""
    items = sorted({norm(r): r for r in roots}.items(), key=lambda kv: len(kv[0]))
    kept: list[tuple[str, str]] = []
    for key, original in items:
        if not any(key == k or key.startswith(k.rstrip("\\/") + os.sep) for k, _ in kept):
            kept.append((key, original))
    return [original for _, original in kept]


def is_excluded(path: str, patterns: Iterable[str]) -> bool:
    text = _slashed(path)
    if not text.endswith("/"):
        text_dir = text + "/"
    else:
        text_dir = text
    return any(fnmatch.fnmatchcase(text, pat) or fnmatch.fnmatchcase(text_dir, pat) for pat in patterns)


def is_within(path: str, parent: str) -> bool:
    child, base = norm(path), norm(parent).rstrip("\\/")
    return child == base or child.startswith(base + os.sep)


_WIN_TEMP = ("/appdata/local/temp/", "/windows/temp/", "/$recycle.bin/", "/temp/", "/tmp/")
_WIN_SYSTEM = ("/windows/system32/", "/windows/syswow64/", "/windows/winsxs/", "/windows/sysnative/")
_WIN_WRITABLE = (
    "/appdata/", "/programdata/", "/users/public/", "/downloads/", "/desktop/", "/documents/",
    "/perflogs/", "/windows/tasks/", "/windows/debug/", "/music/", "/pictures/", "/videos/",
)
_POSIX_TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/", "/run/user/",
               "/var/folders/", "/private/var/folders/")
_POSIX_STARTUP = (
    "/.config/autostart/", "/library/launchagents/", "/library/launchdaemons/", "/etc/cron",
    "/.config/systemd/user/", "/etc/systemd/system/", "/etc/init.d/", "/etc/profile.d/",
)
_POSIX_SYSTEM = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/system/", "/nix/store/")
_POSIX_PROGRAM = ("/opt/", "/applications/", "/snap/", "/var/lib/flatpak/")


def classify_location(path: str, platform: str = sys.platform) -> str:
    """Return startup | temp | user_writable | system | program | other for a file path."""
    text = _slashed(path)
    if not text.endswith("/"):
        text_dir = text.rsplit("/", 1)[0] + "/" if "/" in text else text
    else:
        text_dir = text
    if platform == "win32":
        if "/start menu/programs/startup/" in text_dir:
            return "startup"
        if any(part in text_dir for part in _WIN_TEMP):
            return "temp"
        if any(part in text_dir for part in _WIN_SYSTEM):
            return "system"
        if "/program files/" in text_dir or "/program files (x86)/" in text_dir or "/windowsapps/" in text_dir:
            return "program"
        if any(part in text_dir for part in _WIN_WRITABLE):
            return "user_writable"
        if len(text_dir) <= 3 and text_dir[1:3] == ":/":
            return "user_writable"  # the root of a drive
        if "/windows/" in text_dir:
            return "system"
        return "other"
    if any(part in text_dir for part in _POSIX_STARTUP):
        return "startup"
    if any(text_dir.startswith(part) for part in _POSIX_TEMP):
        return "temp"
    if text_dir.startswith("/usr/local/"):
        return "program"
    if any(text_dir.startswith(part) for part in _POSIX_SYSTEM):
        return "system"
    if any(text_dir.startswith(part) for part in _POSIX_PROGRAM):
        return "program"
    if text_dir.startswith(("/home/", "/users/", "/root/", "/var/www/")):
        return "user_writable"
    return "other"


def basename(path: str) -> str:
    """Final component of a Windows or POSIX path, on any OS."""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def package_data(name: str) -> bytes:
    """Bytes of a file from ``filespy/data``, whether installed normally or bundled into an executable."""
    from importlib import resources

    try:
        return resources.files("filespy").joinpath("data", name).read_bytes()
    except (OSError, ModuleNotFoundError, TypeError, ValueError):
        pass
    bases = [Path(getattr(sys, "_MEIPASS", "")) / "filespy" / "data", Path(__file__).resolve().parent / "data"]
    for base in bases:
        candidate = base / name
        if candidate.is_file():
            return candidate.read_bytes()
    raise FileNotFoundError(f"FileSpy data file is missing: {name}")


def own_folders(data_directory: str | os.PathLike[str]) -> list[str]:
    """Folders that belong to FileSpy itself and must never be monitored."""
    folders = [os.fspath(data_directory)]
    unpacked = getattr(sys, "_MEIPASS", "")  # where a one-file executable unpacks itself
    if unpacked:
        folders.append(unpacked)
    return folders
