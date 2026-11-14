"""Small text helpers shared by the monitors."""

from __future__ import annotations

import difflib
import os
import time


def added_lines(old: str, new: str, limit: int = 20) -> list[str]:
    """Lines present in ``new`` but not in ``old``, ignoring blank lines and comments."""
    out = []
    for line in difflib.ndiff(old.splitlines(), new.splitlines()):
        if line.startswith("+ "):
            text = line[2:].strip()
            if text and not text.startswith("#"):
                out.append(text)
                if len(out) >= limit:
                    break
    return out


def wait_until_quiet(path: str, settle: float = 0.25) -> None:
    """If ``path`` was written a moment ago, wait briefly so a half-written file is not read."""
    try:
        age = time.time() - os.stat(path).st_mtime
    except OSError:
        return
    if 0 <= age < settle:
        time.sleep(settle - age)
