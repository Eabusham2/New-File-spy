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
        removed = False
        try:
            now = os.lstat(path)
            if (now.st_ino, now.st_size, now.st_mtime_ns) == (opened.st_ino, opened.st_size, opened.st_mtime_ns):
                os.remove(path)
                removed = True
        except OSError:
            removed = False
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
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(blob, "rb") as source, open(target, "xb") as out:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk.translate(_TABLE))
        except OSError as exc:
            raise QuarantineError(f"cannot restore to {target}: {exc.strerror or exc}") from exc
        blob.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
        return target

    def delete(self, ident: str) -> QuarantineRecord:
        record = self.get(ident)
        for path in self._paths(record.id):
            path.unlink(missing_ok=True)
        return record
