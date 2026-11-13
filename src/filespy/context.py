"""Everything a monitor needs, bundled."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filespy.analyzer import FileAnalyzer
from filespy.config import Config
from filespy.events import EventBus
from filespy.state import SharedState


@dataclass
class Context:
    config: Config
    bus: EventBus
    data_dir: Path
    state: SharedState = field(default_factory=SharedState)
    analyzer: FileAnalyzer | None = None
    registry: Any = None  # a filespy.registry.RegistryBackend, or None off Windows
    platform: str = sys.platform

    def __post_init__(self) -> None:
        if self.analyzer is None:
            self.analyzer = FileAnalyzer(self.config.detection, self.platform)
