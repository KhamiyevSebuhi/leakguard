"""Git helpers, patch coordinates, index contents and operational errors."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from leakguard.config import Config
from leakguard.errors import GitError
from leakguard.gitutils import (
    added_lines,
    changed_files,
    git,
    repository_root,
    scan_history,
    scan_staged,
    staged_content,
)
from leakguard.ignore import Ignore
from tests.fakes import samples


def test_added_lines() -> None:
    patch_text = "--- a\n+++ b\n@@ -1,2 +2,3 @@\n old\n-deleted\n+new\n+++value\n\\ No newline at end of file\n"
    assert added_lines(patch_text) == [(3, "new"), (4, "++value")]


def test_index_not_disk(repo: Path) -> None:
    path = repo / "space name.env"
    path.write_text(samples()["aws-access-key"])
    git(repo, "add", "--", path.name)
    path.write_text("clean disk")
    assert repository_root(repo) == repo
    assert scan_staged(repo, Config(), Ignore())[0].rule_id == "aws-access-key"
    assert staged_content(repo, Config(max_file_size=1), Ignore()) == []
    assert staged_content(repo, Config(), Ignore(("*.env",))) == []


def test_history_and_range(repo: Path) -> None:
    path = repo / "space [name].env"
    path.write_text("intro\n" + samples()["aws-access-key"] + "\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add")
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    path.write_text("clean\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "remove")
    findings = scan_history(repo, Config(), Ignore())
    assert len(findings) == 1
    assert (findings[0].commit, findings[0].author, findings[0].line) == (commit, "Test Author", 2)
    assert changed_files(repo, commit) == [path.name]
    assert scan_history(repo, Config(), Ignore(), commit) == []
    assert scan_history(repo, Config(), Ignore(("*.env",))) == []
    assert scan_history(repo, Config(max_file_size=1), Ignore()) == []


def test_git_failures(tmp_path: Path) -> None:
    with pytest.raises(GitError):
        repository_root(tmp_path)
    for error in (FileNotFoundError(), subprocess.TimeoutExpired("git", 30)):
        with patch("leakguard.gitutils.subprocess.run", side_effect=error), pytest.raises(GitError):
            git(tmp_path, "status")
