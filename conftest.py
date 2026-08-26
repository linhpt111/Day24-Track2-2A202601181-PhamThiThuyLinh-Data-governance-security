"""Pytest configuration shared by local runs and IDE test discovery."""

from __future__ import annotations

import sys
from pathlib import Path


def pytest_configure(config) -> None:
    """Keep pytest's disposable files away from OneDrive on Windows."""
    if sys.platform == "win32":
        config.option.basetemp = str(Path.home() / "pytest-tmp-day24")
