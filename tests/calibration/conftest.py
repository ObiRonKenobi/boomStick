"""
Calibration lab: Docker-backed checks for HTTP fingerprint capture.

Collect tests with ``@pytest.mark.calibration``. Unless ``BOOMSTICK_RUN_CALIBRATION=1``,
they are skipped so default CI / ``pytest tests/unit`` stays fast.
"""
from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("BOOMSTICK_RUN_CALIBRATION") == "1":
        return
    skip = pytest.mark.skip(reason="Set BOOMSTICK_RUN_CALIBRATION=1 to run calibration lab tests")
    for item in items:
        if item.get_closest_marker("calibration"):
            item.add_marker(skip)
