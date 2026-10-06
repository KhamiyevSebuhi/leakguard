"""Module entry point forwards the CLI result."""

import runpy
from unittest.mock import patch

import pytest


def test_entrypoint() -> None:
    with patch("leakguard.cli.main", return_value=1), pytest.raises(SystemExit) as raised:
        runpy.run_module("leakguard.__main__", run_name="__main__")
    assert raised.value.code == 1
