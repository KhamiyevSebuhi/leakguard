"""Real Git commits exercise installed hooks and baseline workflows."""

import subprocess
from pathlib import Path

from leakguard.cli import main
from leakguard.gitutils import git
from leakguard.hook import install
from tests.fakes import samples


def test_hook_blocks_and_allows(repo: Path) -> None:
    install(repo)
    path = repo / "credentials.env"
    path.write_text(samples()["aws-access-key"])
    git(repo, "add", ".")
    blocked = subprocess.run(["git", "commit", "-m", "blocked"], cwd=repo, capture_output=True, text=True)
    assert blocked.returncode != 0
    combined = blocked.stdout + blocked.stderr
    assert "aws-access-key" in combined
    assert samples()["aws-access-key"] not in combined
    path.write_text("clean\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "allowed")


def test_hook_inline_and_baseline(repo: Path) -> None:
    install(repo)
    path = repo / "credentials.env"
    path.write_text(samples()["aws-access-key"] + " # leakguard:ignore\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "explicit suppression")
    path.write_text(samples()["aws-access-key"])
    assert main(["baseline", "create"]) == 0
    git(repo, "add", ".")
    git(repo, "commit", "-m", "accepted baseline")
    (repo / "new.env").write_text(samples()["github-token"])
    git(repo, "add", ".")
    result = subprocess.run(["git", "commit", "-m", "blocked new"], cwd=repo, capture_output=True)
    assert result.returncode != 0


def test_history_cli(repo: Path, capsys: object) -> None:
    path = repo / "file"
    path.write_text(samples()["aws-access-key"])
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add")
    path.unlink()
    git(repo, "add", "-u")
    git(repo, "commit", "-m", "remove")
    assert main(["scan-history", "--format", "json"]) == 1
