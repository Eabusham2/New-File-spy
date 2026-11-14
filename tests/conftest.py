import pytest

from filespy.config import Config
from filespy.context import Context
from filespy.testing import RecordingBus


@pytest.fixture
def make_ctx(tmp_path):
    """Build a Context whose data directory and settings are private to the test."""

    def build(platform=None, **overrides):
        cfg = Config()
        cfg.files.use_default_paths = False
        cfg.files.settle_seconds = 0.1
        cfg.files.max_settle_seconds = 3.0
        cfg.files.poll_interval = 0.2
        cfg.processes.interval = 0.1
        cfg.network.interval = 0.5
        cfg.autoruns.interval = 0.5
        cfg.settings.interval = 0.5
        for dotted, value in overrides.items():
            cfg.set(dotted.replace("__", "."), value)
        data = tmp_path / "filespy-data"
        data.mkdir(exist_ok=True)
        kwargs = {"platform": platform} if platform else {}
        return Context(config=cfg, bus=RecordingBus(), data_dir=data, **kwargs)

    return build
