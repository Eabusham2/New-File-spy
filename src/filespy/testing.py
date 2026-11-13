"""Helpers for tests (also used by ``filespy selftest``)."""

from __future__ import annotations

import struct
import time
from collections.abc import Callable
from typing import Any

from filespy.events import Event, EventBus

_EICAR_PARTS = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def eicar_bytes() -> bytes:
    """The harmless antivirus test string, assembled at run time so it is never stored whole."""
    return "".join(_EICAR_PARTS).encode("ascii")


_MARKER_PARTS = ("FILESPY-HARMLESS-", "TEST-MARKER-7f3c9a1e52b84d06")


def test_threat_bytes() -> bytes:
    """A harmless marker that FileSpy (and nothing else) reports as critical. Assembled at run time."""
    return ("".join(_MARKER_PARTS) + "\n").encode("ascii")


test_threat_bytes.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def make_pe(sections: tuple[str, ...] = (".text",), dll: bool = False, payload: bytes = b"", signed: bool = False) -> bytes:
    """A structurally valid, non-functional 32-bit PE image for tests."""
    pe_offset = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", pe_offset)
    dos = dos.ljust(pe_offset, b"\x00")
    opt_size = 96 + 16 * 8
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0x5F000000, 0, 0, opt_size, 0x2102 if dll else 0x0102)
    optional = bytearray(opt_size)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 92, 16)
    headers_len = pe_offset + 4 + len(coff) + opt_size + 40 * len(sections)
    raw_ptr = (headers_len + 0x1FF) & ~0x1FF
    table, bodies = b"", b""
    for name in sections:
        body = (payload or b"\x90" * 64).ljust(0x200, b"\x00")
        entry = bytearray(40)
        entry[:8] = name.encode("ascii")[:8].ljust(8, b"\x00")
        struct.pack_into("<IIII", entry, 8, len(body), 0x1000, len(body), raw_ptr + len(bodies))
        struct.pack_into("<I", entry, 36, 0x60000020)
        table += bytes(entry)
        bodies += body
    if signed:
        struct.pack_into("<II", optional, 96 + 4 * 8, raw_ptr + len(bodies), 8)
        bodies += b"\x00" * 8
    image = dos + b"PE\x00\x00" + coff + bytes(optional) + table
    return image.ljust(raw_ptr, b"\x00") + bodies


def make_elf() -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 0x3E) + b"\x00" * 100


def make_lnk(target: str, arguments: str = "") -> bytes:
    """A minimal Windows shortcut pointing at ``target``."""
    flags = 0x2 | 0x80 | (0x20 if arguments else 0)
    header = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046") + struct.pack("<I", flags)
    header = header.ljust(76, b"\x00")
    path = target.encode("cp1252") + b"\x00"
    info_header = 28
    info = struct.pack("<7I", info_header + len(path) + 1, info_header, 0x1, 0, info_header, 0, info_header + len(path))
    info += path + b"\x00"
    strings = b""
    if arguments:
        strings = struct.pack("<H", len(arguments)) + arguments.encode("utf-16-le")
    return header + info + strings


def make_task_actions(path: str, arguments: str = "", context: str = "Author", version: int = 3) -> bytes:
    """A scheduled-task ``Actions`` registry value that runs one program."""

    def packed(text: str) -> bytes:
        raw = text.encode("utf-16-le")
        return struct.pack("<I", len(raw)) + raw

    blob = struct.pack("<H", version) + packed(context) + struct.pack("<H", 0x6666)
    blob += packed("") + packed(path) + packed(arguments) + packed("")
    return blob + (struct.pack("<H", 0) if version >= 3 else b"")


def wait_for(predicate: Callable[[], Any], timeout: float = 10.0, interval: float = 0.05) -> Any:
    """Poll until ``predicate`` returns something truthy or the timeout passes; return its last value."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(interval)


class RecordingBus(EventBus):
    """An EventBus that remembers everything published."""

    def __init__(self) -> None:
        super().__init__(session="test")
        self.events: list[Event] = []
        self.subscribe(self.events.append)

    def find(self, category: str | None = None, action: str | None = None, indicator: str | None = None) -> list[Event]:
        out = []
        for event in list(self.events):
            if category and event.category != category:
                continue
            if action and event.action != action:
                continue
            if indicator and not any(i.id == indicator or i.id.startswith(indicator) for i in event.indicators):
                continue
            out.append(event)
        return out
