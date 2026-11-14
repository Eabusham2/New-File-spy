"""Content signatures: plain substrings in a JSON file, no regular expressions.

Each rule lists strings (searched as ASCII and as UTF-16LE), how many must be
present, and which file kinds it applies to. Substring search is linear, so a
hostile file cannot make a rule run for a long time.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filespy.events import Indicator, Severity
from filespy.paths import package_data

log = logging.getLogger("filespy")

#: SHA-256 -> name. The EICAR test file is the only built-in entry.
BUILTIN_BAD_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR antivirus test file",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR antivirus test file",
}


@dataclass
class Rule:
    id: str
    name: str
    description: str
    score: int
    kinds: frozenset[str]
    needles: list[tuple[bytes, bytes]]  # (ascii form, utf-16le form), lower-cased when nocase
    min_match: int = 1
    nocase: bool = False
    floor: Severity | None = None
    mitre: str = ""

    def matches(self, data: bytes, lowered: bytes) -> bool:
        haystack = lowered if self.nocase else data
        hits = 0
        remaining = len(self.needles)
        for plain, wide in self.needles:
            if plain in haystack or wide in haystack:
                hits += 1
                if hits >= self.min_match:
                    return True
            remaining -= 1
            if hits + remaining < self.min_match:
                return False
        return False


def _parse_rule(raw: dict[str, Any]) -> Rule:
    nocase = bool(raw.get("nocase", False))
    needles = []
    for item in raw["strings"]:
        text = "".join(item["parts"]) if isinstance(item, dict) else str(item)
        if len(text) < 4:
            raise ValueError(f"rule {raw.get('id')}: string too short")
        if nocase:
            text = text.lower()
        needles.append((text.encode("utf-8"), text.encode("utf-16-le")))
    if not needles:
        raise ValueError(f"rule {raw.get('id')}: no strings")
    floor = raw.get("floor")
    return Rule(
        id=str(raw["id"]),
        name=str(raw.get("name", raw["id"])),
        description=str(raw.get("description", raw.get("name", raw["id"]))),
        score=int(raw.get("score", 50)),
        kinds=frozenset(raw.get("kinds", [])),
        needles=needles,
        min_match=max(1, min(int(raw.get("min_match", 1)), len(needles))),
        nocase=nocase,
        floor=Severity.parse(floor) if floor else None,
        mitre=str(raw.get("mitre", "")),
    )


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def load_text(self, text: str, source: str) -> None:
        try:
            doc = json.loads(text)
            items = doc["rules"] if isinstance(doc, dict) else doc
        except (ValueError, KeyError, TypeError) as exc:
            self.errors.append(f"{source}: {exc}")
            return
        for raw in items:
            try:
                self.rules.append(_parse_rule(raw))
            except (KeyError, ValueError, TypeError) as exc:
                self.errors.append(f"{source}: bad rule {raw!r:.80}: {exc}")

    def match(self, data: bytes, kind: str) -> list[Indicator]:
        if not data:
            return []
        lowered = data.lower() if any(r.nocase for r in self.rules) else data
        out = []
        for rule in self.rules:
            if rule.kinds and kind not in rule.kinds:
                continue
            if rule.matches(data, lowered):
                out.append(Indicator(f"file.rule.{rule.id}", rule.score, f"Matches signature: {rule.name}", rule.mitre, rule.floor))
        return out


def builtin_rules_bytes() -> bytes:
    return package_data("rules.json")


def builtin_rules_text() -> str:
    return builtin_rules_bytes().decode("utf-8")


def builtin_rules_hashes() -> set[str]:
    """SHA-256 of the built-in rule file as installed and with either kind of line ending.

    A checkout on Windows may convert line endings, so one hash is not enough to
    recognise a copy of our own rule file.
    """
    raw = builtin_rules_bytes()
    unix = raw.replace(b"\r\n", b"\n")
    return {hashlib.sha256(data).hexdigest() for data in (raw, unix, unix.replace(b"\n", b"\r\n"))}


def load_rules(extra_files: list[str] | None = None) -> RuleSet:
    ruleset = RuleSet()
    ruleset.load_text(builtin_rules_text(), "built-in rules")
    for name in extra_files or []:
        try:
            ruleset.load_text(Path(name).read_text(encoding="utf-8"), name)
        except OSError as exc:
            ruleset.errors.append(f"{name}: {exc}")
    return ruleset


def load_hash_list(files: list[str]) -> dict[str, str]:
    """Read hash lists: one MD5 or SHA-256 per line, optional comment after the hash."""
    out: dict[str, str] = {}
    for name in files:
        try:
            with open(name, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    token, _, comment = line.strip().partition(" ")
                    token = token.split(",")[0].split("#")[0].strip().lower()
                    if len(token) in (32, 64) and all(c in "0123456789abcdef" for c in token):
                        out[token] = comment.strip(" #") or Path(name).name
        except OSError as exc:
            log.warning("hash list %s not readable: %s", name, exc)
    return out
