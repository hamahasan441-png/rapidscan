"""
Conftest for rapidscan tests.

The rapidscan module executes code at import time (argument parsing,
shuffling, etc.), so we need to mock sys.argv before importing it.
This conftest provides a shared fixture that handles the import safely.
"""
import sys
import importlib
from unittest import mock

import pytest


@pytest.fixture(scope="session")
def rapidscan_module():
    """Import the rapidscan module with mocked sys.argv so that top-level
    code does not call sys.exit or attempt to scan a real target."""
    with mock.patch.object(sys, "argv", ["rapidscan.py", "--help"]):
        # Remove cached module if any so we get a fresh import
        sys.modules.pop("rapidscan", None)
        mod = importlib.import_module("rapidscan")
    return mod
