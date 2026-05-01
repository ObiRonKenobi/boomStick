from __future__ import annotations

import os

import pytest

pytest_plugins = ["tests.plugins.cursor_report"]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("BOOMSTICK_RUN_INTEGRATION") == "1":
        return
    skip_int = pytest.mark.skip(reason="Set BOOMSTICK_RUN_INTEGRATION=1 and start tests/compose stack")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_int)
