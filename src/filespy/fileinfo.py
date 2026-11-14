"""Bounded, crash-proof inspection of a file that may be hostile.

Nothing here executes, imports or follows links into the file being inspected.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import BinaryIO

NATIVE_KINDS = frozenset({"pe", "elf", "macho"})
RUNNABLE_KINDS = frozenset({"pe", "elf", "macho", "script", "lnk"})

NATIVE_EXTS = frozenset({
    "exe", "dll", "scr", "com", "pif", "cpl", "sys", "ocx", "drv", "efi", "msi", "msp", "mst",
    "so", "dylib", "kext", "bin", "elf", "appimage", "run", "out",
})
SCRIPT_EXTS = frozenset({
    "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "sct", "wsc",
    "reg", "inf", "jar", "py", "pyw", "sh", "bash", "zsh", "command", "scpt", "applescript", "pl", "rb",
    "php", "lua", "msc", "xsl", "application", "appref-ms", "settingcontent-ms", "desktop", "service", "plist",
})
#: Script types that run when opened, as opposed to library source code.
CLICKABLE_SCRIPT_EXTS = frozenset({
    "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "sct", "wsc", "jar", "reg", "msc",
    "command", "scpt", "desktop", "application", "appref-ms", "settingcontent-ms",
})
SHORTCUT_EXTS = frozenset({"lnk", "url", "scf", "library-ms", "search-ms", "website"})
MACRO_EXTS = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "xll", "xlsb", "one", "chm"})
CONTAINER_EXTS = frozenset({"iso", "img", "vhd", "vhdx", "cab", "zip", "rar", "7z", "msix", "appx", "dmg", "pkg"})
RISKY_EXTS = NATIVE_EXTS | SCRIPT_EXTS | SHORTCUT_EXTS | MACRO_EXTS
#: Extensions people expect to be harmless documents or media; a program hiding behind one is a trick.
DECOY_EXTS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "bmp",
    "mp3", "mp4", "avi", "mkv", "mov", "wav", "csv", "log", "dat", "ini", "xml", "json", "html", "htm",
})
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack", "pec1": "PECompact",
    "pec2": "PECompact", ".packed": "generic packer", ".rlpack": "RLPack", ".perplex": "Perplex",
}
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


class NotRegularFile(OSError):
    """Raised for links, directories, devices, pipes and sockets - things we refuse to open."""


def extension(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(". ")
    return base.rsplit(".", 1)[-1].lower() if "." in base[1:] else ""


def open_regular(path: str) -> BinaryIO:
    """Open ``path`` for reading only if it is a regular file, never following a final symlink."""
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise NotRegularFile(f"not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(f"not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


def hash_stream(handle: BinaryIO, limit: int) -> tuple[str, str, int]:
    """SHA-256 and MD5 of up to ``limit`` bytes; returns ("", "", n) if the file is larger."""
    sha, md5, seen = hashlib.sha256(), hashlib.md5(), 0  # noqa: S324 - md5 only for blocklist lookups
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        seen += len(chunk)
        if seen > limit:
            return "", "", seen
        sha.update(chunk)
        md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest(), seen


def looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or head[:3] == b"\xef\xbb\xbf":
        return True
    sample = head[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 0x80)
    return printable / len(sample) > 0.9


def detect_kind(head: bytes, name: str = "") -> str:
    """Classify by magic bytes first, extension second.

    Returns one of: pe, elf, macho, script, lnk, ole, zip, rar, 7z, cab, pdf, rtf, chm,
    gzip, bzip2, xz, javaclass, html, text, empty, data.
    """
    if not head:
        return "empty"
    ext = extension(name)
    if head[:2] == b"MZ" and len(head) >= 0x40:
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if offset + 4 > len(head) or head[offset:offset + 4] == b"PE\x00\x00":
            return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        return "macho" if struct.unpack_from(">I", head, 4)[0] < 40 else "javaclass"
    if head[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        return "lnk"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    for magic, kind in (
        (b"PK\x03\x04", "zip"), (b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"MSCF", "cab"),
        (b"%PDF", "pdf"), (b"{\\rtf", "rtf"), (b"ITSF", "chm"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
    ):
        if head.startswith(magic):
            return kind
    if head[:2] == b"#!":
        return "script"
    if looks_like_text(head):
        if ext in ("hta", "html", "htm", "svg", "xhtml"):
            return "html"
        if ext in SCRIPT_EXTS and ext not in ("plist", "desktop", "service", "inf", "reg"):
            return "script"
        lowered = head[:2048].lower()
        if b"<html" in lowered or b"<script" in lowered:
            return "html"
        return "text"
    return "data"


@dataclass
class PEInfo:
    is_dll: bool = False
    is_dotnet: bool = False
    is_64bit: bool = False
    signed: bool = False  # an Authenticode blob is present (not verified)
    timestamp: int = 0
    sections: list[tuple[str, float, int]] = field(default_factory=list)  # name, entropy, raw size
    max_entropy: float = 0.0
    packer: str = ""
    writable_code: bool = False
    overlay: int = 0


def parse_pe(data: bytes, file_size: int | None = None) -> PEInfo | None:
    """Minimal PE header parse. Returns None for anything malformed; never raises."""
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
            return None
        _machine, nsections, timestamp, _sym, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", data, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return None
        info = PEInfo(is_dll=bool(chars & 0x2000), is_64bit=magic == 0x20B, timestamp=timestamp)
        dirs_at = opt + (96 if magic == 0x10B else 112)
        ndirs = min(struct.unpack_from("<I", data, dirs_at - 4)[0], 16)
        sec_off = sec_size = 0
        if ndirs > 4 and dirs_at + 5 * 8 <= len(data):
            sec_off, sec_size = struct.unpack_from("<II", data, dirs_at + 4 * 8)
            info.signed = sec_size > 0
        if ndirs > 14 and dirs_at + 15 * 8 <= len(data):
            info.is_dotnet = struct.unpack_from("<II", data, dirs_at + 14 * 8)[1] > 0
        table = opt + opt_size
        end_of_image = 0
        for index in range(min(nsections, 96)):
            base = table + index * 40
            if base + 40 > len(data):
                break
            raw_name = data[base:base + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("latin-1")
            raw_size, raw_ptr = struct.unpack_from("<II", data, base + 16)
            flags = struct.unpack_from("<I", data, base + 36)[0]
            body = data[raw_ptr:raw_ptr + min(raw_size, 4 * 1024 * 1024)] if raw_ptr < len(data) else b""
            ent = round(shannon_entropy(body), 2) if body else 0.0
            info.sections.append((name, ent, raw_size))
            info.max_entropy = max(info.max_entropy, ent)
            end_of_image = max(end_of_image, raw_ptr + raw_size)
            if name.lower() in PACKER_SECTIONS and not info.packer:
                info.packer = PACKER_SECTIONS[name.lower()]
            if flags & 0x20000000 and flags & 0x80000000:
                info.writable_code = True
        if file_size and end_of_image:
            overlay = file_size - end_of_image
            if sec_size and sec_off >= end_of_image:
                overlay -= sec_size  # the signature lives after the last section
            info.overlay = max(0, overlay)
        return info
    except (struct.error, IndexError, ValueError, OverflowError):
        return None


def read_zone_identifier(path: str) -> dict[str, str] | None:
    """Mark-of-the-Web on Windows: where a downloaded file came from. None if absent."""
    if os.name != "nt":
        return None
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as handle:
            text = handle.read(4096)
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            if key.strip() in ("ZoneId", "ReferrerUrl", "HostUrl"):
                out[key.strip()] = value.strip()[:500]
    return out or None


def is_hidden(path: str, info: os.stat_result | None = None) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    if os.name == "nt":
        try:
            attrs = (info or os.lstat(path)).st_file_attributes  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            return False
        return bool(attrs & 0x2)
    return name.startswith(".")
