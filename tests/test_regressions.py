"""Named reproductions of bugs found during implementation and self-scanning."""

from pathlib import Path

import pytest

from leakguard.gitutils import git
from leakguard.hook import install
from leakguard.scanner import scan_text
from tests.fakes import samples


@pytest.mark.parametrize("expression", ["re.compile(pattern)", "samples()[name]", "value.split(':')", "os.environ['KEY']"])
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
    assert all(first not in f.redacted_snippet and second not in f.redacted_snippet for f in findings)
