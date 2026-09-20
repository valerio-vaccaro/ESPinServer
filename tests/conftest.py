import os

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--pinserver-url",
        action="store",
        default=os.getenv("PINSERVER_URL", "http://espinserver.local"),
        help="Base URL of the running ESPinServer (default: PINSERVER_URL or espinserver.local).",
    )
    parser.addoption(
        "--run-capacity",
        action="store_true",
        default=False,
        help="Run the destructive 16-slot capacity test (disabled by default).",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-capacity"):
        return
    skip_capacity = pytest.mark.skip(reason="capacity test disabled by default; use --run-capacity")
    for item in items:
        if "pin_database_has_exactly_16_slots" in item.name:
            item.add_marker(skip_capacity)
