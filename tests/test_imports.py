"""Smoke tests that every module imports and its public entry points resolve.

These would have caught the `NameError: name 'SMBClient' is not defined`
regression that a pure-logic classifier test cannot see, since it only shows up
once go_snaffle is actually imported and its names are referenced.
"""

import importlib

import pytest


@pytest.mark.parametrize("module", [
    "snaffler",
    "snaffcore.classifier",
    "snaffcore.go_snaffle",
    "snaffcore.smb",
    "snaffcore.file_handling",
    "snaffcore.utilities",
    "snaffcore.errors",
    "snaffcore.logger",
])
def test_module_imports(module):
    importlib.import_module(module)


def test_go_snaffle_entry_points_resolve():
    g = importlib.import_module("snaffcore.go_snaffle")
    # Names referenced inside begin_snaffle / snaffle_directory / process_file.
    for name in ("SMBClient", "RemoteFile", "FileRetrievalError",
                 "FileListError", "Rules", "is_interest_share",
                 "classify_directory", "classify_file_name",
                 "classify_file_content", "check_for_keys",
                 "begin_snaffle", "snaffle_directory", "process_file"):
        assert hasattr(g, name), f"go_snaffle is missing '{name}'"
