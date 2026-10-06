"""Text scanning, bounded I/O and traversal behavior."""

from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leakguard.config import Config
from leakguard.errors import LeakGuardError
from leakguard.ignore import Ignore
from leakguard.scanner import scan_bytes, scan_directory, scan_file, scan_text
from tests.fakes import samples


@given(st.text(max_size=1000))
def test_determinism(text: str) -> None:
    assert scan_text(text, "file") == scan_text(text, "file")


@given(st.integers(min_value=0, max_value=30))
def test_line_shift(count: int) -> None:
    text = samples()["aws-access-key"]
    original = scan_text(text, "file")
    shifted = scan_text("clean\n" * count + text, "file")
    assert [f.fingerprint for f in original] == [f.fingerprint for f in shifted]
    assert shifted[0].line == original[0].line + count


def test_filters() -> None:
    value = samples()["aws-access-key"]
    assert scan_text(value + " # leakguard:ignore", "file") == []
    assert scan_text(value, "file", Config(disabled_rules=("aws-access-key", "high-entropy"))) == []
    assert scan_text('password="changeme"', "file") == []
    assert scan_bytes(b"\0" + value.encode(), "file") == []
    assert scan_bytes(value.encode(), "file", Config(max_file_size=2)) == []
    assert scan_bytes(b"\xff" + value.encode(), "file")


def test_directory(tmp_path: Path) -> None:
    (tmp_path / "yes.txt").write_text(samples()["aws-access-key"])
    (tmp_path / "ignore.txt").write_text(samples()["aws-access-key"])
    for name in (".git", "node_modules", ".venv"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "secret").write_text(samples()["aws-access-key"])
    found = scan_directory(tmp_path, ignore=Ignore(("ignore.txt",)))
    assert {f.file for f in found} == {"yes.txt"}
    assert scan_file(tmp_path / "yes.txt", tmp_path, Config(max_file_size=1)) == []
    assert scan_file(tmp_path / ".git" / "secret", tmp_path) == []


def test_file_errors(tmp_path: Path) -> None:
    with pytest.raises(LeakGuardError):
        scan_file(tmp_path / "missing", tmp_path)
    path = tmp_path / "file"
    path.write_text("clean")
    with patch.object(Path, "open", side_effect=PermissionError), pytest.raises(LeakGuardError):
        scan_file(path, tmp_path)
    with patch("leakguard.scanner.os.walk", side_effect=lambda *a, **kw: kw["onerror"](PermissionError())):
        with pytest.raises(LeakGuardError):
            scan_directory(tmp_path)


def test_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text(samples()["aws-access-key"])
    assert scan_file(outside, root) == []
    link = root / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        return  # Windows may lack symlink privilege; boundary above remains tested.
    assert scan_file(link, root) == []
