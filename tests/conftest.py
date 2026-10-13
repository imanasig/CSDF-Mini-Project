import pytest


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    """All app tests use disposable persistence, never the real local runtime."""
    monkeypatch.setenv("CYBERTRAIL_DATA_DIR", str(tmp_path / "app-runtime"))
