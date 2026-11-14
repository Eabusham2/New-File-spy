"""File-based and kernel settings (hosts file, accounts, sudo, SSH, sysctl) and macOS protections."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from filespy import sanitize
from filespy.context import Context
from filespy.settingsmon import Change
from filespy.textutil import added_lines, wait_until_quiet

MAX_FILE = 262144
_SECURITY_HOSTS = re.compile(
    r"(microsoft|windowsupdate|windows\.com|defender|virustotal|kaspersky|avast|avg\.|bitdefender|malwarebytes|"
    r"eset\.|symantec|norton|mcafee|sophos|trendmicro|f-secure|avira|drweb|comodo|clamav|apple\.com|mozilla|"
    r"ubuntu\.com|debian\.org|archive\.|security\.|update)",
    re.IGNORECASE,
)
Scorer = Callable[[list[str]], "tuple[int, str] | None"]


def score_hosts(lines: list[str]) -> tuple[int, str] | None:
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and any(_SECURITY_HOSTS.search(host) for host in fields[1:]):
            return 85, "The hosts file now blocks or redirects security or update websites"
    return None


def score_passwd(lines: list[str]) -> tuple[int, str] | None:
    for line in lines:
        fields = line.split(":")
        if len(fields) >= 4 and fields[2] == "0" and fields[0] != "root":
            return 85, "A new account with full administrator (root) rights was added"
    return (45, "A user account was added") if lines else None


def score_sudoers(lines: list[str]) -> tuple[int, str] | None:
    if any("NOPASSWD" in line or re.search(r"ALL\s*=\s*\(?\s*ALL", line) for line in lines):
        return 70, "Administrator (sudo) rights were granted"
    return None


def score_sshd(lines: list[str]) -> tuple[int, str] | None:
    pattern = re.compile(r"^\s*(PermitRootLogin\s+yes|PermitEmptyPasswords\s+yes|AuthorizedKeysFile|ForceCommand)", re.IGNORECASE)
    if any(pattern.search(line) for line in lines):
        return 60, "The SSH server was reconfigured in a way that eases remote access"
    return None


@dataclass
class WatchedFile:
    id: str
    path: str
    category: str
    message: str
    score: int
    scorer: Scorer | None = None
    mitre: str = ""
    secret: bool = False  # never keep or show the contents (password hashes)


def _digest_dir(path: str) -> dict[str, str] | None:
    try:
        names = sorted(os.listdir(path))[:500]
    except OSError:
        return None
    out = {}
    for name in names:
        full = os.path.join(path, name)
        try:
            if os.path.isfile(full) and os.path.getsize(full) <= MAX_FILE:
                with open(full, "rb") as handle:
                    out[name] = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            continue
    return out


class FileSettingsProvider:
    """Watches configuration files (by content) and directories (by the hash of each file)."""

    name = "config-files"
    every = 1

    def __init__(self, files: list[WatchedFile]) -> None:
        self.files = {item.id: item for item in files}

    def snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for ident, item in self.files.items():
            if os.path.isdir(item.path):
                out[ident] = _digest_dir(item.path)
                continue
            try:
                if not os.path.isfile(item.path):
                    out[ident] = None
                    continue
                wait_until_quiet(item.path)
                with open(item.path, "rb") as handle:
                    raw = handle.read(MAX_FILE)
            except OSError:
                out[ident] = None
                continue
            state = {"hash": hashlib.sha256(raw).hexdigest()}
            if not item.secret:
                state["text"] = raw.decode("utf-8", "replace")
            out[ident] = state
        return out

    def changes(self, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
        out = []
        for ident, item in self.files.items():
            before, after = old.get(ident), new.get(ident)
            if before == after:
                continue
            details: dict[str, Any] = {"setting": ident}
            score, title = item.score, item.message
            danger = False
            if isinstance(after, dict) and "hash" not in after:  # a directory
                previous = before if isinstance(before, dict) else {}
                details["changed_files"] = sorted(n for n in after if previous.get(n) != after[n])[:20]
                details["removed_files"] = sorted(n for n in previous if n not in after)[:20]
            elif after is None:
                title = f"{item.message} (the file was removed or can no longer be read)"
            elif not item.secret:
                lines = added_lines((before or {}).get("text", ""), after.get("text", ""), limit=200)
                details["added_lines"] = [sanitize.clean(line, 300) for line in lines[:20]]
                details["added_line_count"] = len(lines)
                verdict = item.scorer(lines) if item.scorer else None
                if verdict:
                    score, title = verdict
                    danger = True
                elif before is not None and not lines:
                    score = min(score, 15)  # lines were only removed
            out.append(Change(ident, item.category, title, item.path, score, danger, item.mitre, details))
        return out

    def audit(self, snapshot: dict[str, Any]) -> list[Change]:
        out = []
        for ident, item in self.files.items():
            state = snapshot.get(ident)
            if item.scorer and isinstance(state, dict) and "text" in state:
                lines = [line.strip() for line in state["text"].splitlines() if line.strip() and not line.lstrip().startswith("#")]
                verdict = item.scorer(lines) if item.id.startswith("hosts") else None
                if verdict:
                    out.append(Change(ident, item.category, verdict[1], item.path, verdict[0], True, item.mitre, {"setting": ident}))
        return out


#: (id, file under /proc/sys, safe-value test, message, score)
SYSCTLS: tuple[tuple[str, str, Callable[[str], bool], str, int], ...] = (
    ("sysctl_aslr", "kernel/randomize_va_space", lambda v: v == "2", "Memory-layout randomisation (ASLR) was weakened", 55),
    ("sysctl_ptrace", "kernel/yama/ptrace_scope", lambda v: v != "0", "Any program may now inspect other programs (ptrace protection off)", 40),
    ("sysctl_kptr", "kernel/kptr_restrict", lambda v: v != "0", "Kernel addresses are no longer hidden", 30),
    ("sysctl_dmesg", "kernel/dmesg_restrict", lambda v: v != "0", "Kernel logs are readable by every user again", 20),
    ("sysctl_core_pattern", "kernel/core_pattern", lambda v: not v.startswith("|") or "systemd-coredump" in v or "apport" in v,
     "Crashing programs are now piped to a custom command (core_pattern)", 60),
)


class SysctlProvider:
    name = "kernel-settings"
    every = 1

    def __init__(self, root: str = "/proc/sys") -> None:
        self.root = root

    def snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for ident, relative, _safe, _message, _score in SYSCTLS:
            try:
                with open(os.path.join(self.root, relative), encoding="utf-8", errors="replace") as handle:
                    out[ident] = handle.read(512).strip()
            except OSError:
                out[ident] = None
        return out

    def _findings(self, old: dict[str, Any] | None, new: dict[str, Any]) -> list[Change]:
        out = []
        for ident, relative, safe, message, score in SYSCTLS:
            value = new.get(ident)
            if value is None or (old is not None and old.get(ident) == value):
                continue
            danger = not safe(value)
            if old is None and not danger:
                continue
            title = message if danger else f"A kernel security setting changed ({relative.replace('/', '.')})"
            details = {"setting": ident, "new": sanitize.clean(value, 200)}
            if old is not None:
                details["old"] = sanitize.clean(old.get(ident), 200)
            out.append(Change(ident, "kernel", title, "/proc/sys/" + relative, score if danger else 15, danger, "T1562", details))
        return out

    def changes(self, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
        return self._findings(old, new)

    def audit(self, snapshot: dict[str, Any]) -> list[Change]:
        return self._findings(None, snapshot)


#: (id, argument list with an absolute path, text that means "protected", message, score)
MAC_COMMANDS: tuple[tuple[str, list[str], str, str, int], ...] = (
    ("mac_gatekeeper", ["/usr/sbin/spctl", "--status"], "assessments enabled", "Gatekeeper was switched off", 80),
    ("mac_sip", ["/usr/bin/csrutil", "status"], "enabled", "System Integrity Protection was switched off", 80),
    ("mac_firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "enabled",
     "The macOS firewall was switched off", 55),
    ("mac_filevault", ["/usr/bin/fdesetup", "status"], "FileVault is On", "FileVault disk encryption was switched off", 55),
)


class MacCommandProvider:
    name = "macos-protections"
    every = 6

    def __init__(self, runner: Callable[[list[str]], str | None] | None = None) -> None:
        self._run = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list[str]) -> str | None:
        if not os.path.isfile(argv[0]):
            return None
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=8, check=False, stdin=subprocess.DEVNULL)  # noqa: S603
        except (OSError, subprocess.SubprocessError):
            return None
        return (done.stdout + done.stderr)[:2000].strip()

    def snapshot(self) -> dict[str, Any]:
        return {ident: self._run(argv) for ident, argv, _ok, _message, _score in MAC_COMMANDS}

    def _findings(self, old: dict[str, Any] | None, new: dict[str, Any]) -> list[Change]:
        out = []
        for ident, argv, ok, message, score in MAC_COMMANDS:
            value = new.get(ident)
            if value is None or (old is not None and old.get(ident) == value):
                continue
            danger = ok.lower() not in value.lower()
            if old is None and not danger:
                continue
            title = message if danger else f"A macOS protection setting changed ({ident})"
            out.append(Change(ident, "macos", title, " ".join(argv), score if danger else 15, danger, "T1562.001",
                              {"setting": ident, "new": sanitize.clean(value, 200)}))
        return out

    def changes(self, old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
        return self._findings(old, new)

    def audit(self, snapshot: dict[str, Any]) -> list[Change]:
        return self._findings(None, snapshot)


def posix_files(platform: str) -> list[WatchedFile]:
    files = [
        WatchedFile("hosts_file", "/etc/hosts", "hosts", "The hosts file was changed", 30, score_hosts, "T1565.001"),
        WatchedFile("resolv_conf", "/etc/resolv.conf", "dns", "The DNS servers were changed", 15, None, "T1565"),
        WatchedFile("passwd", "/etc/passwd", "accounts", "The user account list was changed", 20, score_passwd, "T1136.001"),
        WatchedFile("group", "/etc/group", "accounts", "Group memberships were changed", 30, None, "T1098"),
        WatchedFile("shadow", "/etc/shadow", "accounts", "A password was changed or an account was added", 30, None, "T1098", secret=True),
        WatchedFile("sudoers", "/etc/sudoers", "privilege", "The sudo rules were changed", 40, score_sudoers, "T1548.003"),
        WatchedFile("sudoers_d", "/etc/sudoers.d", "privilege", "A sudo rule file was added or changed", 55, None, "T1548.003"),
        WatchedFile("sshd_config", "/etc/ssh/sshd_config", "remote_access", "The SSH server configuration was changed", 30, score_sshd, "T1021.004"),
        WatchedFile("pam_d", "/etc/pam.d", "authentication", "The login (PAM) configuration was changed", 50, None, "T1556.003"),
    ]
    if platform != "darwin":
        files.append(WatchedFile("environment", "/etc/environment", "environment", "System-wide environment variables were changed", 30, None, "T1574.007"))
        files.append(WatchedFile("nsswitch", "/etc/nsswitch.conf", "dns", "The name-lookup order was changed", 30, None, "T1565"))
    return files


def providers(ctx: Context) -> list:
    out: list = [FileSettingsProvider(posix_files(ctx.platform))]
    if ctx.platform == "darwin":
        out.append(MacCommandProvider())
    elif os.path.isdir("/proc/sys"):
        out.append(SysctlProvider())
    return out
