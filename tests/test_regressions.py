"""Named reproductions of bugs found during implementation and self-scanning."""

from pathlib import Path

import pytest

from leakguard.baseline import load_baseline
from leakguard.config import Config
from leakguard.errors import BaselineError
from leakguard.gitutils import git, scan_history
from leakguard.hook import install
from leakguard.ignore import Ignore
from leakguard.scanner import scan_text
from tests.fakes import samples


@pytest.mark.parametrize(
    "expression",
    ["re.compile(pattern)", "samples()[name]", "value.split(':')", "os.environ['KEY']"],
)
def test_python_expression_is_not_literal(expression: str) -> None:
    # Self-scanning initially reported regex objects and function calls as credentials.
    assert scan_text("token = " + expression, "source.py") == []


def test_hook_does_not_import_repository_module(repo: Path) -> None:
    # Review found that plain python -m could import a repository's leakguard.py.
    (repo / "leakguard.py").write_text('raise RuntimeError("must not execute")\n')
    install(repo)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "isolated interpreter")


def test_overlapping_report_masks_entire_line() -> None:
    # Report only the match mask; surrounding source may contain another credential.
    first = samples()["aws-access-key"]
    second = samples()["github-token"]
    findings = scan_text(first + " " + second, "file")
    assert len(findings) == 2
    assert all(
        first not in f.redacted_snippet and second not in f.redacted_snippet for f in findings
    )


def test_deep_json_raises_domain_error(tmp_path: Path) -> None:
    # Adversarial review found JSON recursion escaped the baseline exception contract.
    path = tmp_path / "baseline"
    path.write_text("[" * 2000 + "]" * 2000)
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_binary_history_ignores_forced_text_diff(repo: Path) -> None:
    # Attributes can force text diffs for binary blobs; inspect the blob itself.
    (repo / ".gitattributes").write_text("*.dat diff\n")
    (repo / "binary.dat").write_bytes(b"\0\n" + samples()["aws-access-key"].encode())
    git(repo, "add", ".")
    git(repo, "commit", "-m", "binary")
    assert scan_history(repo, Config(), Ignore()) == []


def test_merge_does_not_reattribute_ancestor_patch(repo: Path) -> None:
    # Review found path-limited git log could walk back and label an ancestor's
    # patch with the merge hash. --no-walk restricts each query to that commit.
    (repo / "clean").write_text("clean")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "root")
    git(repo, "checkout", "-b", "side")
    (repo / "side").write_text("clean side")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "side change")
    git(repo, "checkout", "main")
    (repo / "credential").write_text(samples()["aws-access-key"])
    git(repo, "add", ".")
    git(repo, "commit", "-m", "main addition")
    original = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "merge", "--no-ff", "side", "-m", "merge side")
    findings = scan_history(repo, Config(), Ignore())
    assert len(findings) == 1
    assert findings[0].commit == original
