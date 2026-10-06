"""In-process CLI contracts and safe errors."""

from pathlib import Path
from unittest.mock import patch

import pytest

from leakguard.cli import main
from leakguard.gitutils import git
from tests.fakes import samples


def test_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "file.env"
    path.write_text(samples()["generic-secret"])
    assert main(["scan", "file.env", "--no-color"]) == 1
    assert "generic-secret" in capsys.readouterr().out
    assert main(["scan", "--min-severity", "HIGH"]) == 0
    assert main(["scan", "--format", "sarif"]) == 1
    assert main(["scan", "--format", "json", "--max-file-size", "2"]) == 0
    assert main(["scan", "--max-file-size", "0"]) == 2
    assert main(["scan", "missing"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_commands(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    assert "aws-access-key" in capsys.readouterr().out
    assert main(["--version"]) == 0
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main(["hook", "install"]) == 0
    assert main(["hook", "uninstall"]) == 0
    assert main(["hook", "uninstall"]) == 0
    assert main(["scan", "--staged", "file"]) == 2
    assert main(["scan", "--staged"]) == 0
    assert main(["scan-history"]) == 0


def test_baseline(repo: Path) -> None:
    (repo / "a.env").write_text(samples()["aws-access-key"])
    assert main(["baseline", "create"]) == 0
    assert main(["scan"]) == 0
    (repo / "b.env").write_text(samples()["github-token"])
    assert main(["scan", "--baseline", ".leakguard-baseline.json"]) == 1
    git(repo, "add", "a.env")
    assert main(["scan", "--staged"]) == 0


def test_safe_errors(capsys: pytest.CaptureFixture[str]) -> None:
    value = samples()["aws-access-key"]
    assert main(["scan", "--format", value]) == 2
    assert value not in capsys.readouterr().err
    for error in (OSError(value), ValueError(value), KeyboardInterrupt()):
        with patch("leakguard.cli._run", side_effect=error):
            assert main(["scan"]) == 2
        assert value not in capsys.readouterr().err
