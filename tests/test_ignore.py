"""Documented glob and inline suppression semantics."""

from pathlib import Path

import pytest

from leakguard.errors import ConfigError
from leakguard.ignore import Ignore, inline_ignored, load_ignore


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.log", "nested/a.log", True),
        ("vendor/", "src/vendor/a", True),
        ("/build/out/", "build/out/a", True),
        ("src/*.py", "src/a.py", True),
        ("vendor/", "vendorish/a", False),
        ("*.txt", "a.py", False),
    ],
)
def test_matches(pattern: str, path: str, expected: bool) -> None:
    assert Ignore((pattern,)).matches(path) is expected


def test_inline() -> None:
    assert inline_ignored("x # leakguard:ignore", "jwt")
    assert inline_ignored("x // leakguard:ignore=jwt", "jwt")
    assert not inline_ignored("x # leakguard:ignore=jwt", "github-token")
    assert not inline_ignored("leakguard:ignore", "jwt")
    assert not inline_ignored("x # leakguard:ignoreTYPO", "jwt")


def test_load(tmp_path: Path) -> None:
    path = tmp_path / "ignore"
    assert load_ignore(path, ("a",)).patterns == ("a",)
    path.write_text("# comment\n\n*.txt\nvendor/\n")
    assert load_ignore(path).patterns == ("*.txt", "vendor/")
    path.write_bytes(b"\xff")
    with pytest.raises(ConfigError):
        load_ignore(path)
