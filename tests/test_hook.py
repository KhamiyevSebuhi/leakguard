"""Ownership checks and portable shell hook content."""

from pathlib import Path
from unittest.mock import patch

import pytest

from leakguard.errors import GitError
from leakguard.hook import hook_path, hook_script, install, uninstall


def test_hook_lifecycle(repo: Path) -> None:
    assert not uninstall(repo)
    path = install(repo)
    assert path == hook_path(repo)
    assert "-m leakguard scan --staged" in path.read_text()
    install(repo)
    assert uninstall(repo)
    path.write_text("#!/bin/sh\necho foreign\n")
    with pytest.raises(GitError):
        install(repo)
    with pytest.raises(GitError):
        uninstall(repo)
    install(repo, force=True)
    assert uninstall(repo)


def test_quoted_interpreter() -> None:
    script = hook_script("C:\\Program Files\\Python\\python.exe")
    assert "'C:/Program Files/Python/python.exe'" in script
    assert script.startswith("#!/bin/sh\n")


def test_errors(repo: Path) -> None:
    with patch.object(Path, "write_text", side_effect=PermissionError), pytest.raises(GitError):
        install(repo)
    install(repo)
    with patch.object(Path, "unlink", side_effect=PermissionError), pytest.raises(GitError):
        uninstall(repo)
