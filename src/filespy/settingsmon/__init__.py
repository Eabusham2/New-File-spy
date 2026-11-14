"""Security-relevant settings: what is watched, and how a change is described."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from filespy.context import Context


@dataclass
class Change:
    """One setting that changed (or, in an audit, one setting currently in a dangerous state)."""

    id: str
    category: str
    title: str  # plain-English sentence shown to the user
    subject: str  # registry value or file
    score: int
    danger: bool
    mitre: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class SettingsProvider(Protocol):
    name: str
    every: int  # poll on every Nth tick (expensive providers use a larger number)

    def snapshot(self) -> dict[str, Any]: ...

    def changes(self, old: dict[str, Any], new: dict[str, Any]) -> list[Change]: ...

    def audit(self, snapshot: dict[str, Any]) -> list[Change]: ...


def get_providers(ctx: Context) -> list[SettingsProvider]:
    from filespy.settingsmon import posix

    if ctx.platform == "win32":
        from filespy.settingsmon import windows

        out: list[SettingsProvider] = []
        if ctx.registry is not None:
            out.append(windows.WindowsSettingsProvider(ctx.registry, ctx.config.settings.max_tier))
        out.append(posix.FileSettingsProvider(windows.watched_files()))
        return out
    return posix.providers(ctx)
