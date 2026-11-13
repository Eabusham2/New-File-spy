"""Helpers for strings that malware can control (file names, command lines, registry data).

Nothing from the monitored machine is ever printed, logged or exported without
going through one of these.
"""

from __future__ import annotations

import unicodedata

# Bidi controls and zero-width characters used to disguise file names.
_INVISIBLE = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF,
}
BIDI_OVERRIDES = frozenset({0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068})


def _visible(ch: str) -> str:
    code = ord(ch)
    if code in _INVISIBLE:
        return f"<U+{code:04X}>"
    if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
        return {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(ch, f"\\x{code:02x}")
    if 0xD800 <= code <= 0xDFFF:
        return f"\\u{code:04x}"
    if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
        return f"<U+{code:04X}>"
    return ch


def clean(value: object, max_len: int = 500) -> str:
    """One safe line: control characters, ANSI escapes and bidi tricks made visible."""
    text = value if isinstance(value, str) else str(value)
    truncated = len(text) > max_len
    if truncated:
        text = text[:max_len]
    out = "".join(_visible(ch) for ch in text)
    return out + "..." if truncated else out


def has_bidi_or_invisible(text: str) -> bool:
    return any(ord(ch) in _INVISIBLE for ch in text)


def csv_cell(value: object, max_len: int = 4000) -> str:
    """Clean text that a spreadsheet will not treat as a formula."""
    text = clean(value, max_len)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def json_safe(value: object, depth: int = 0) -> object:
    """Make arbitrary detail values JSON-serialisable without raising."""
    if depth > 6:
        return clean(repr(value), 200)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, bytes):
        return value[:256].hex()
    if isinstance(value, dict):
        return {str(k): json_safe(v, depth + 1) for k, v in list(value.items())[:500]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(v, depth + 1) for v in list(value)[:500]]
    return clean(str(value), 500)
