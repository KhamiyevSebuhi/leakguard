"""Digest-only baseline validation, atomicity and round trips."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leakguard.baseline import load_baseline, save_baseline
from leakguard.errors import BaselineError


@given(st.sets(st.binary(min_size=32, max_size=32).map(bytes.hex), max_size=20))
def test_roundtrip(values: set[str]) -> None:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "baseline.json"
        save_baseline(path, values)
        assert load_baseline(path) == values


@pytest.mark.parametrize(
    "text",
    [
        "",
        "null",
        "[]",
        "{}",
        '{"version": 2, "fingerprints": []}',
        '{"version": true, "fingerprints": []}',
        '{"version": 1, "fingerprints": ["secret"]}',
        '{"version": 1, "fingerprints": 3}',
    ],
)
def test_invalid(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad"
    path.write_text(text)
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_failures(tmp_path: Path) -> None:
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "missing")
    with pytest.raises(BaselineError):
        save_baseline(tmp_path / "bad", {"bad"})
    with patch("leakguard.baseline.os.replace", side_effect=PermissionError):
        with pytest.raises(BaselineError):
            save_baseline(tmp_path / "bad", {"a" * 64})
    assert list(tmp_path.iterdir()) == []
