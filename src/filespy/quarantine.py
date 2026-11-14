"""Quarantine: move a file out of harm's way in a form that cannot run, and bring it back if wanted.

The stored copy is XOR-scrambled, so it is inert and other tools will not trip over it.
Links are never followed, and the original is only removed if it is still the file that
was copied.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from filespy import fileinfo
from filespy.paths import ensure_private_dir, is_within

_KEY = 0xA5
_ID = re.compile(r"^[0-9a-f]{32}$")
_TABLE = bytes(b ^ _KEY for b in range(256))
MAX_SIZE = 2 * 1024 * 1024 * 1024


class QuarantineError(Exception):
    pass


def _remove_exact_windows(path: str, opened: os.stat_result) -> bool:
    """Delete the file behind ``path`` through a handle, after checking it is the file we copied."""
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD),
        ]

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", ctypes.c_ubyte)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    kernel32.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    delete_access, read_attributes, share_all, open_existing, open_reparse_point = 0x00010000, 0x80, 0x7, 3, 0x00200000
    handle = kernel32.CreateFileW(path, delete_access | read_attributes, share_all, None, open_existing, open_reparse_point, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        info = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return False
        if info.dwFileAttributes & (0x400 | 0x10):  # a link, a junction or a directory is never deleted
            return False
        index = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        if index != (opened.st_ino & 0xFFFFFFFFFFFFFFFF) or info.dwVolumeSerialNumber != (opened.st_dev & 0xFFFFFFFF):
            return False
        disposition = FileDispositionInfo(1)
        return bool(kernel32.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)))
    finally:
        kernel32.CloseHandle(handle)


def remove_exact(path: str, opened: os.stat_result) -> bool:
    """Delete ``path`` only if it is still the very file described by ``opened``; True if it was removed.

    The check and the delete go through a directory or file handle, so swapping a folder
    in the path for a link between the two steps cannot redirect the delete elsewhere.
    """
    if os.name == "nt":
        try:
            return _remove_exact_windows(path, opened)
        except (OSError, AttributeError, ValueError):
            return False
    folder, name = os.path.split(os.path.abspath(path))
    try:
        dir_fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return False
    try:
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            return False
        os.unlink(name, dir_fd=dir_fd)
        return True
    except OSError:
        return False
    finally:
        os.close(dir_fd)


def link_in_path(path: str) -> bool:
    """True if any existing folder on the way to ``path`` is a symbolic link or a junction."""
    current = os.path.abspath(path)
    while True:
        try:
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return True
        except OSError:
            pass
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


@dataclass
class QuarantineRecord:
    id: str
    original_path: str
    sha256: str
    size: int
    ts: float
    reason: str = ""
    original_removed: bool = True


class Quarantine:
    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir)
        self.folder = self.data_dir / "quarantine"

    def _paths(self, ident: str) -> tuple[Path, Path]:
        if not _ID.match(ident):
            raise QuarantineError(f"not a quarantine id: {ident!r}")
        return self.folder / f"{ident}.bin", self.folder / f"{ident}.json"

    def add(self, path: str, reason: str = "", expected_sha256: str = "") -> QuarantineRecord:
        """Copy ``path`` into quarantine and delete the original."""
        if is_within(path, str(self.data_dir)):
            raise QuarantineError("refusing to quarantine FileSpy's own files")
        ensure_private_dir(self.folder)
        ident = uuid.uuid4().hex
        blob, meta = self._paths(ident)
        digest = hashlib.sha256()
        size = 0
        try:
            with fileinfo.open_regular(path) as source:
                opened = os.fstat(source.fileno())
                if opened.st_size > MAX_SIZE:
                    raise QuarantineError("file is too large to quarantine")
                with open(blob, "xb") as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        digest.update(chunk)
                        target.write(chunk.translate(_TABLE))
        except OSError as exc:
            blob.unlink(missing_ok=True)
            raise QuarantineError(f"cannot read {path}: {exc.strerror or exc}") from exc
        except QuarantineError:
            blob.unlink(missing_ok=True)
            raise
        sha256 = digest.hexdigest()
        if expected_sha256 and sha256 != expected_sha256:
            blob.unlink(missing_ok=True)
            raise QuarantineError("the file changed after it was examined; nothing was quarantined")
        removed = remove_exact(path, opened)
        record = QuarantineRecord(ident, os.path.abspath(path), sha256, size, time.time(), reason[:500], removed)
        meta.write_text(json.dumps(asdict(record), indent=2), encoding="utf-8")
        return record

    def list(self) -> list[QuarantineRecord]:
        out = []
        if not self.folder.is_dir():
            return out
        for meta in sorted(self.folder.glob("*.json")):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
                if _ID.match(str(data.get("id", ""))) and (self.folder / f"{data['id']}.bin").exists():
                    out.append(QuarantineRecord(**{k: data[k] for k in QuarantineRecord.__dataclass_fields__ if k in data}))
            except (OSError, ValueError, TypeError, KeyError):
                continue
        return sorted(out, key=lambda r: r.ts)

    def get(self, ident: str) -> QuarantineRecord:
        for record in self.list():
            if record.id == ident or (len(ident) >= 6 and record.id.startswith(ident)):
                return record
        raise QuarantineError(f"no quarantined file with id {ident}")

    def restore(self, ident: str, destination: str | None = None) -> Path:
        """Write the original bytes back (never over an existing file) and drop the quarantined copy."""
        record = self.get(ident)
        blob, meta = self._paths(record.id)
        target = Path(destination or record.original_path)
        if target.exists() or target.is_symlink():
            raise QuarantineError(f"{target} already exists; choose another place with --to")
        if is_within(str(target), str(self.data_dir)):
            raise QuarantineError("refusing to restore into FileSpy's own folder")
        if destination is None and link_in_path(str(target.parent)):
            # The folder the file came from may belong to whoever dropped it; if it has been turned
            # into a link, restoring there would write the file somewhere of their choosing.
            raise QuarantineError("the original folder is now reached through a link; choose a place with --to")
        created = False
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with open(blob, "rb") as source, os.fdopen(os.open(target, flags, 0o600), "wb") as out:
                created = True
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk.translate(_TABLE))
        except OSError as exc:
            if created:
                try:
                    os.unlink(target)  # never leave half a file behind
                except OSError:
                    pass
            raise QuarantineError(f"cannot restore to {target}: {exc.strerror or exc}") from exc
        blob.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
        return target

    def delete(self, ident: str) -> QuarantineRecord:
        record = self.get(ident)
        for path in self._paths(record.id):
            path.unlink(missing_ok=True)
        return record
