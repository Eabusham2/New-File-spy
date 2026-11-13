"""Work out which file an autostart command really launches.

"rundll32 C:\\x\\evil.dll,Run" launches evil.dll, not rundll32; "cmd /c start a.exe"
launches a.exe. Best effort: when unsure, the first program on the line is returned.
"""

from __future__ import annotations

import re
import shlex

_EXT = r"(?:exe|dll|bat|cmd|com|scr|pif|cpl|sys|ocx|msi|vbs|vbe|js|jse|wsf|wsh|ps1|hta|lnk|jar|py)"
_FIRST_PATH = re.compile(rf"(.+?\.{_EXT})(?=[\s,]|$)", re.IGNORECASE)
_ARG = re.compile(r'"[^"]*"|\S+')
HOSTS = frozenset({
    "rundll32", "regsvr32", "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "msiexec",
    "conhost", "explorer", "forfiles",
})


def _base(path: str) -> str:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _args(text: str) -> list[str]:
    return [a.strip('"') for a in _ARG.findall(text)]


def split_first(command: str) -> tuple[str, str]:
    """Split a Windows command line into (program, rest), coping with unquoted paths with spaces."""
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 0:
            return text[1:end], text[end + 1:].strip()
        return text[1:], ""
    token, _, rest = text.partition(" ")
    if _base(token) in HOSTS or re.search(rf"\.{_EXT}$", token, re.IGNORECASE) or "\\" not in text:
        return token, rest.strip()
    match = _FIRST_PATH.match(text)
    if match:
        return match.group(1), text[match.end():].strip()
    return token, rest.strip()


def _payload(host: str, rest: str, depth: int) -> str:
    args = _args(rest)
    if host == "rundll32":
        text = rest.strip()
        if text.startswith('"'):
            end = text.find('"', 1)
            return text[1:end] if end > 0 else ""
        return text.split(",", 1)[0].strip()
    if host == "regsvr32":
        plain = [a for a in args if not a.startswith(("/", "-"))]
        return plain[-1] if plain else ""
    if host in ("wscript", "cscript"):
        plain = [a for a in args if not a.startswith("//")]
        return plain[0] if plain else ""
    if host in ("mshta", "explorer"):
        return args[0] if args else ""
    if host in ("powershell", "pwsh"):
        for index, arg in enumerate(args[:-1]):
            if arg.lower() in ("-file", "-f", "/file"):
                return args[index + 1]
        return ""
    if host == "msiexec":
        for index, arg in enumerate(args):
            low = arg.lower()
            if low in ("/i", "/package", "-i", "/a") and index + 1 < len(args):
                return args[index + 1]
            if low.startswith("/i") and len(arg) > 2:
                return arg[2:]
        return ""
    if host == "cmd":
        match = re.search(r"(?:^|\s)/[ck]\s+(.*)$", rest, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        inner = match.group(1).strip()
        if inner.startswith('"') and inner.endswith('"') and inner.count('"') == 2:
            inner = inner[1:-1]
        start = re.match(r'start\s+(?:"[^"]*"\s+)?(?:/\w+\s+)*', inner, re.IGNORECASE)
        if start:
            inner = inner[start.end():]
        return extract_target(inner, depth + 1)
    if host == "conhost":
        remaining = [a for a in args if not a.startswith("--")]
        return extract_target(" ".join(remaining), depth + 1) if remaining else ""
    if host == "forfiles":
        match = re.search(r'/c\s+"?(.*?)"?\s*$', rest, re.IGNORECASE)
        return extract_target(match.group(1), depth + 1) if match else ""
    return ""


def extract_target(command: str, depth: int = 0) -> str:
    """Path of the program, library or script a Windows command line launches ("" if empty)."""
    if not command or not command.strip() or depth > 4:
        return ""
    first, rest = split_first(command)
    host = _base(first)
    if host in HOSTS:
        return _payload(host, rest, depth) or first
    return first


def normalise_service_path(image_path: str) -> str:
    """Service ImagePath values use NT forms such as ``\\SystemRoot\\...`` and ``\\??\\C:\\...``."""
    text = image_path.strip()
    if text.startswith("\\??\\"):
        text = text[4:]
    low = text.lower()
    if low.startswith("\\systemroot\\"):
        text = "%SystemRoot%" + text[11:]
    elif low.startswith(("system32\\", "syswow64\\")):
        text = "%SystemRoot%\\" + text
    return text


_WRAPPERS = frozenset({"sudo", "env", "nohup", "setsid", "exec", "time", "nice", "ionice", "command"})
_INTERPRETERS = re.compile(r"^(?:sh|bash|zsh|dash|ksh|fish|python[\d.]*|perl|ruby|node|php|osascript)$")


def extract_posix_target(command: str) -> str:
    """First real program (or the script handed to an interpreter) in a POSIX command line."""
    try:
        tokens = shlex.split(command, comments=False)
    except ValueError:
        tokens = command.split()
    index = 0
    wrapped = False
    while index < len(tokens):
        token = tokens[index]
        if token.rsplit("/", 1)[-1] in _WRAPPERS:
            wrapped = True
        elif not (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token) or (wrapped and token.startswith("-"))):
            break
        index += 1
    if index >= len(tokens):
        return ""
    program = tokens[index]
    if _INTERPRETERS.match(program.rsplit("/", 1)[-1]):
        for arg in tokens[index + 1:]:
            if arg == "-c":
                break
            if not arg.startswith("-"):
                return arg
    return program
