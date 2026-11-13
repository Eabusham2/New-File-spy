"""Windows registry access behind a small interface, plus an in-memory fake for tests.

Values are normalised: text -> str, DWORD/QWORD -> int, MULTI_SZ -> list[str], binary -> bytes.
A missing key or value is reported as None; nothing here raises for "not found".
"""

from __future__ import annotations

import os
import re
from typing import Any, Protocol

HIVES = ("HKLM", "HKCU", "HKU", "HKCR")
_ENV_REF = re.compile(r"%([^%]+)%")


def expand_env(text: str, env: dict[str, str] | None = None) -> str:
    """Expand %NAME% references case-insensitively; unknown names are left as they are."""
    source = os.environ if env is None else env
    lowered = {k.lower(): v for k, v in source.items()}
    return _ENV_REF.sub(lambda m: lowered.get(m.group(1).lower(), m.group(0)), text)


class RegistryBackend(Protocol):
    def values(self, hive: str, key: str) -> dict[str, Any] | None: ...

    def subkeys(self, hive: str, key: str) -> list[str] | None: ...

    def get(self, hive: str, key: str, name: str) -> Any: ...

    def expand(self, text: str) -> str: ...


def _lookup(values: dict[str, Any] | None, name: str) -> Any:
    if values is None:
        return None
    if name in values:
        return values[name]
    wanted = name.lower()
    for key, data in values.items():
        if key.lower() == wanted:
            return data
    return None


class WinRegistry:
    """Real registry, read-only, always through the 64-bit view."""

    def __init__(self) -> None:
        import winreg  # only importable on Windows

        self._w = winreg
        self._roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS, "HKCR": winreg.HKEY_CLASSES_ROOT,
        }
        self._access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY

    def _open(self, hive: str, key: str):  # noqa: ANN202
        try:
            return self._w.OpenKey(self._roots[hive], key, 0, self._access)
        except (OSError, KeyError):
            return None

    @staticmethod
    def _normalise(data: Any) -> Any:
        if data is None:
            return ""
        if isinstance(data, list):
            return [str(item) for item in data]
        return data

    def values(self, hive: str, key: str) -> dict[str, Any] | None:
        handle = self._open(hive, key)
        if handle is None:
            return None
        out: dict[str, Any] = {}
        with handle:
            index = 0
            while index < 10000:
                try:
                    name, data, _kind = self._w.EnumValue(handle, index)
                except OSError:
                    break
                out[name] = self._normalise(data)
                index += 1
        return out

    def subkeys(self, hive: str, key: str) -> list[str] | None:
        handle = self._open(hive, key)
        if handle is None:
            return None
        out: list[str] = []
        with handle:
            index = 0
            while index < 20000:
                try:
                    out.append(self._w.EnumKey(handle, index))
                except OSError:
                    break
                index += 1
        return out

    def get(self, hive: str, key: str, name: str) -> Any:
        handle = self._open(hive, key)
        if handle is None:
            return None
        with handle:
            try:
                data, _kind = self._w.QueryValueEx(handle, name)
            except OSError:
                return None
        return self._normalise(data)

    def expand(self, text: str) -> str:
        try:
            return self._w.ExpandEnvironmentStrings(text)
        except (OSError, TypeError, ValueError):
            return text


class FakeRegistry:
    """In-memory registry for tests. Key and value names are case-insensitive, like the real thing."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        self._keys: dict[tuple[str, str], dict[str, Any]] = {}
        self._names: dict[tuple[str, str], str] = {}
        self.env = env or {
            "SystemRoot": r"C:\Windows", "windir": r"C:\Windows", "ProgramFiles": r"C:\Program Files",
            "APPDATA": r"C:\Users\test\AppData\Roaming", "LOCALAPPDATA": r"C:\Users\test\AppData\Local",
            "TEMP": r"C:\Users\test\AppData\Local\Temp", "ProgramData": r"C:\ProgramData",
            "USERPROFILE": r"C:\Users\test", "PUBLIC": r"C:\Users\Public",
        }

    @staticmethod
    def _id(hive: str, key: str) -> tuple[str, str]:
        return hive, key.strip("\\").lower()

    def create_key(self, hive: str, key: str) -> None:
        parts = key.strip("\\").split("\\")
        for depth in range(1, len(parts) + 1):
            path = "\\".join(parts[:depth])
            ident = self._id(hive, path)
            self._keys.setdefault(ident, {})
            self._names.setdefault(ident, parts[depth - 1])

    def set(self, hive: str, key: str, name: str, data: Any) -> None:
        self.create_key(hive, key)
        values = self._keys[self._id(hive, key)]
        for existing in list(values):
            if existing.lower() == name.lower():
                del values[existing]
        values[name] = data

    def delete_value(self, hive: str, key: str, name: str) -> None:
        values = self._keys.get(self._id(hive, key), {})
        for existing in list(values):
            if existing.lower() == name.lower():
                del values[existing]

    def delete_key(self, hive: str, key: str) -> None:
        ident = self._id(hive, key)
        for other in list(self._keys):
            if other[0] == hive and (other[1] == ident[1] or other[1].startswith(ident[1] + "\\")):
                del self._keys[other]
                self._names.pop(other, None)

    def values(self, hive: str, key: str) -> dict[str, Any] | None:
        values = self._keys.get(self._id(hive, key))
        return None if values is None else dict(values)

    def subkeys(self, hive: str, key: str) -> list[str] | None:
        ident = self._id(hive, key)
        if ident not in self._keys:
            return None
        prefix = ident[1] + "\\" if ident[1] else ""
        return sorted(
            self._names[other] for other in self._keys
            if other[0] == hive and other[1].startswith(prefix) and other[1] != ident[1]
            and "\\" not in other[1][len(prefix):]
        )

    def get(self, hive: str, key: str, name: str) -> Any:
        return _lookup(self._keys.get(self._id(hive, key)), name)

    def expand(self, text: str) -> str:
        return expand_env(text, self.env)


def make_registry() -> RegistryBackend | None:
    """The real registry on Windows, None elsewhere."""
    if os.name != "nt":
        return None
    try:
        return WinRegistry()
    except ImportError:
        return None
