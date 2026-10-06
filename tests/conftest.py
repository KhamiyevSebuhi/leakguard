"""Deterministic Hypothesis settings and isolated Git/golden fixtures."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import settings

from tests.fakes import samples

settings.register_profile("ci", max_examples=50, derandomize=True, deadline=None)
settings.load_profile("ci")


def pytest_addoption(parser: pytest.Parser) -> None:
    """Expose explicit golden regeneration."""
    parser.addoption("--update-golden", action="store_true", default=False)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a repository isolated from user configuration and real repositories."""
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    for args in (
        ("init", "-b", "main"),
        ("config", "user.name", "Test Author"),
        ("config", "user.email", "test@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("config", "core.autocrlf", "false"),
    ):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


@pytest.fixture
def golden_fixture(tmp_path: Path) -> Path:
    """Expand a committed template into a disposable fixture directory."""
    template = Path(__file__).parent / "golden" / "fixture"
    shutil.copytree(template, tmp_path / "fixture")
    target = tmp_path / "fixture"
    data = (target / "sample.template").read_text(encoding="utf-8")
    (target / "sample.template").unlink()
    (target / "sample.env").write_text(
        data.replace("{{FAKE_ACCESS_KEY}}", samples()["aws-access-key"]), encoding="utf-8"
    )
    return target
