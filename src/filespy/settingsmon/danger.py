"""Evaluates the "is this change dangerous?" rules stored with each catalog entry.

A rule is a small JSON tree, for example ``{"op": "eq", "value": 1}`` or
``{"op": "any", "of": [...]}``. State rules (eq, in, present, ...) look only at the new
value; transition rules (appeared, left, from_to, decrease, added, ...) compare old and
new. In an audit there is no old value, so transition rules are false there.
"""

from __future__ import annotations

import re
from typing import Any

MAX_TEXT = 4000


def split_items(value: Any, how: str) -> set[str]:
    """Break a list-like setting into lower-cased items."""
    if value is None:
        return set()
    if isinstance(value, list):
        parts = [str(item) for item in value]
    else:
        text = str(value)
        if how == "multi":
            parts = text.split("\x00")
        elif how == "dns":
            parts = re.split(r"[,\s]+", text)
        else:
            parts = text.split(how)
    return {part.strip().lower() for part in parts if part.strip()}


def same(a: Any, b: Any) -> bool:
    if a == b:
        return True
    if a is None or b is None or isinstance(a, (bytes, list, dict)) or isinstance(b, (bytes, list, dict)):
        return False
    return str(a).strip().lower() == str(b).strip().lower()


def _in(value: Any, candidates: list[Any]) -> bool:
    return any(same(value, candidate) for candidate in candidates)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _present(kind: str, value: Any) -> bool:
    if kind == "key":
        return bool(value)
    if kind in ("value_map", "subkeys"):
        return bool(value)
    return value is not None


def _names(kind: str, entry: dict[str, Any], value: Any) -> set[str]:
    if kind == "value_map":
        return {str(name).lower() for name in value} if isinstance(value, dict) else set()
    if kind == "subkeys":
        return {str(name).lower() for name in value} if isinstance(value, list) else set()
    if "split" in entry:
        return split_items(value, entry["split"])
    return set()


def evaluate(rule: dict[str, Any], entry: dict[str, Any], old: Any, new: Any, transition: bool = True) -> bool:
    """True if ``new`` (reached from ``old``) is the dangerous case this rule describes."""
    if not isinstance(rule, dict):
        return False
    op = rule.get("op")
    kind = entry.get("kind", "value")
    if op == "any":
        return any(evaluate(sub, entry, old, new, transition) for sub in rule.get("of", []))
    if op == "all":
        return all(evaluate(sub, entry, old, new, transition) for sub in rule.get("of", []))

    def effective(value: Any) -> Any:
        return entry["absent_as"] if value is None and "absent_as" in entry else value

    now, before = effective(new), effective(old)
    if op == "present":
        return _present(kind, new)
    if op == "absent":
        return not _present(kind, new)
    if op == "eq":
        return now is not None and same(now, rule.get("value"))
    if op == "ieq":
        return now is not None and same(now, rule.get("value"))
    if op == "ne":
        return now is not None and not same(now, rule.get("value"))
    if op in ("in", "iin"):
        return now is not None and _in(now, rule.get("values", []))
    if op == "lt":
        number = _number(now)
        return number is not None and number < float(rule.get("value", 0))
    if op in ("regex", "not_regex"):
        if not isinstance(new, str):
            return False
        found = re.search(rule.get("pattern", ""), new[:MAX_TEXT]) is not None
        return found if op == "regex" else not found
    if op == "svc_off":
        values = rule.get("values", [4])
        return new is not None and _in(new, values) and not (transition and old is not None and _in(old, values))
    known = {str(item).lower() for item in entry.get("known", [])}
    if op == "named_value_in":
        pattern, values = rule.get("name_regex", ""), rule.get("values", [])
        for name, data in (new or {}).items() if isinstance(new, dict) else ():
            if re.search(pattern, str(name)) and _in(data, values):
                if not transition or not isinstance(old, dict) or not same(old.get(name), data):
                    return True
        return False
    if not transition:
        if op == "added" and "split" in entry:  # unknown items present right now
            return bool(_names(kind, entry, new) - known)
        if op == "named_added" and isinstance(new, dict):
            return any(re.search(rule.get("name_regex", ""), str(name)) for name in new)
        return False
    # ---- transition rules ----
    if op == "appeared":
        return not _present(kind, old) and _present(kind, new)
    if op == "changed":
        return old != new
    if op == "decrease":
        a, b = _number(before), _number(now)
        return a is not None and b is not None and b < a
    if op == "left":
        values = rule.get("values", [])
        return before is not None and _in(before, values) and not _in(now, values)
    if op == "from_to":
        return _in(before, rule.get("frm", [])) and _in(now, rule.get("to", []))
    if op == "added":
        return bool(_names(kind, entry, new) - _names(kind, entry, old) - known)
    if op == "removed":
        return bool(_names(kind, entry, old) - _names(kind, entry, new))
    if op == "named_added":
        fresh = _names(kind, entry, new) - _names(kind, entry, old)
        return any(re.search(rule.get("name_regex", ""), name) for name in fresh)
    if op == "custom":
        if kind in ("value_map", "subkeys"):
            return bool(_names(kind, entry, new) - _names(kind, entry, old))
        return new is not None and str(new).strip() != "" and old != new
    return False
