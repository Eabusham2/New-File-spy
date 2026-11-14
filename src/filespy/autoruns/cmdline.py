"""Work out which file an autostart command really launches.

"rundll32 C:\\x\\evil.dll,Run" launches evil.dll, not rundll32; "cmd /c start a.exe"
launches a.exe. Best effort: when unsure, the first program on the line is returned.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable

_EXT = r"(?:exe|dll|bat|cmd|com|scr|pif|cpl|sys|ocx|msi|vbs|vbe|js|jse|wsf|wsh|ps1|hta|lnk|jar|py)"
_EXT_END = re.compile(rf"\.{_EXT}(?=[\s,]|$)", re.IGNORECASE)
_HAS_EXT = re.compile(rf"\.{_EXT}$", re.IGNORECASE)
_SCRIPT_LIKE = re.compile(rf"\.(?:{_EXT[3:-1]}|psm1|psd1|pl|rb|php|sh|class)$", re.IGNORECASE)
_ARG = re.compile(r'(?:[^\s"]|"[^"]*")+')
_INTERPRETERS_WIN = frozenset({"python", "pythonw", "py", "node", "perl", "ruby", "php"})
HOSTS = frozenset({
    "rundll32", "regsvr32", "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "msiexec",
    "conhost", "explorer", "forfiles", "java", "javaw",
}) | _INTERPRETERS_WIN
Exists = Callable[[str], bool]


def _base(path: str) -> str:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _args(text: str) -> list[str]:
    return [a.replace('"', "") for a in _ARG.findall(text)]


def split_first(command: str, exists: Exists | None = None) -> tuple[str, str]:
    """Split a Windows command line into (program, rest).

    An unquoted path may contain spaces. Windows tries each prefix that ends at a space
    and runs the first one that exists; ``exists`` lets us do the same on a real system.
    Without it, the shortest prefix that ends in a program extension is taken.
    """
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 0:
            return text[1:end], text[end + 1:].strip()
        return text[1:], ""
    token, _, rest = text.partition(" ")
    has_path = "\\" in token or re.match(r"^[A-Za-z]:", token) is not None
    if not has_path or _base(token) in HOSTS:
        return token, rest.strip()
    candidates = [match.end() for match in _EXT_END.finditer(text)]
    if exists is not None:
        for end in candidates:
            if exists(text[:end]):
                return text[:end], text[end:].strip()
    if _HAS_EXT.search(token):
        return token, rest.strip()
    if candidates:
        first = text[:candidates[0]]
        # A switch inside the supposed path means the program name really ended at the first space.
        if not re.search(r"\s[-/]\w", first):
            return first, text[candidates[0]:].strip()
    return token, rest.strip()


def _payload(host: str, rest: str, depth: int, exists: Exists | None) -> str:
    args = _args(rest)
    if host == "rundll32":
        text = rest.strip()
        if text.startswith('"'):
            end = text.find('"', 1)
            return text[1:end] if end > 0 else ""
        part = text.split(",", 1)[0].strip()
        match = re.match(r"(.+?\.[A-Za-z0-9]{1,4})(?=\s|$)", part)  # "x.dll Run" is also accepted by rundll32
        return match.group(1) if match else part
    if host == "regsvr32":
        plain = [a for a in args if not a.startswith(("/", "-"))]
        return plain[-1] if plain else ""
    if host in ("wscript", "cscript"):
        plain = [a for a in args if not a.startswith("//")]
        return plain[0] if plain else ""
    if host in ("mshta", "explorer"):
        return args[0] if args else ""
    if host in ("powershell", "pwsh"):
        for index, arg in enumerate(args):
            if arg.lower() in ("-file", "-f", "/file") and index + 1 < len(args):
                return args[index + 1]
            joined = re.match(r"^[-/]f(?:ile)?[=:](.+)$", arg, re.IGNORECASE)
            if joined:
                return joined.group(1)
        for index, arg in enumerate(args):
            if arg.lower() in ("-command", "-c", "/command") and index + 1 < len(args):
                inner = " ".join(args[index + 1:]).lstrip("&. ").strip("'\" ")
                first = inner.split()[0].strip("'\"") if inner else ""
                return first if _SCRIPT_LIKE.search(first) or "\\" in first else ""
        for arg in args:
            if not arg.startswith(("-", "/")) and (_SCRIPT_LIKE.search(arg) or "\\" in arg):
                return arg
        return ""
    if host == "msiexec":
        for index, arg in enumerate(args):
            low = arg.lower()
            if low in ("/i", "/package", "-i", "/a") and index + 1 < len(args):
                return args[index + 1]
            if low.startswith(("/i", "-i")) and len(arg) > 2:
                return arg[2:]
        return ""
    if host in ("java", "javaw"):
        for index, arg in enumerate(args[:-1]):
            if arg.lower() == "-jar":
                return args[index + 1]
        return ""
    if host in _INTERPRETERS_WIN:
        for arg in args:
            if arg in ("-c", "-e", "-m", "-r"):
                return ""  # inline code or a module, not a file
            if not arg.startswith("-"):
                return arg
        return ""
    if host == "cmd":
        match = re.search(r'(?:^|\s)/[ck](?=\s|"|$)\s*(.*)$', rest, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        inner = match.group(1).strip()
        if len(inner) >= 2 and inner.startswith('"') and inner.endswith('"'):
            inner = inner[1:-1]  # cmd itself drops the first and the last quote
        start = re.match(r'start\s+(?:"[^"]*"\s+)?(?:/\w+\s+)*', inner, re.IGNORECASE)
        if start:
            inner = inner[start.end():]
        return extract_target(inner, depth + 1, exists)
    if host == "conhost":
        remaining = [a for a in args if not a.startswith("--")]
        return extract_target(" ".join(remaining), depth + 1, exists) if remaining else ""
    if host == "forfiles":
        match = re.search(r'/c\s+"?(.*?)"?\s*$', rest, re.IGNORECASE)
        return extract_target(match.group(1), depth + 1, exists) if match else ""
    return ""


def extract_target(command: str, depth: int = 0, exists: Exists | None = None) -> str:
    """Path of the program, library or script a Windows command line launches ("" if empty)."""
    if not command or not command.strip() or depth > 4:
        return ""
    first, rest = split_first(command, exists)
    host = _base(first)
    if host in HOSTS:
        return _payload(host, rest, depth, exists) or first
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
