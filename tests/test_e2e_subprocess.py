"""Subprocess exit contracts with an explicitly constructed environment."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.fakes import samples


@pytest.mark.parametrize(
    ("content", "args", "code"),
    [
        ("ordinary text", ["scan", "file", "--format", "json"], 0),
        ("sensitive", ["scan", "file", "--format", "json"], 1),
        ("ordinary text", ["scan", "missing"], 2),
        ("ordinary text", ["unknown"], 2),
    ],
)
def test_process(tmp_path: Path, content: str, args: list[str], code: int) -> None:
    data = samples()["aws-access-key"] if content == "sensitive" else content
    (tmp_path / "file").write_text(data)
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-I", "-m", "leakguard", *args],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == code
    assert "Traceback" not in result.stdout + result.stderr
    assert samples()["aws-access-key"] not in result.stdout + result.stderr
    if code in (0, 1):
        assert bool(json.loads(result.stdout)["findings"]) == (code == 1)
        assert not result.stderr
    else:
        assert result.stderr
