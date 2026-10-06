"""Bounded Unicode, malformed inputs, and binary robustness properties."""

from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given
from hypothesis import strategies as st

from leakguard.baseline import load_baseline
from leakguard.config import load_config
from leakguard.errors import LeakGuardError
from leakguard.scanner import scan_bytes, scan_text


@given(st.text(max_size=4000))
def test_unicode(text: str) -> None:
    assert isinstance(scan_text(text, "fuzz.txt"), list)


@given(st.binary(max_size=4000))
def test_bytes(data: bytes) -> None:
    assert isinstance(scan_bytes(data, "fuzz.txt"), list)


@given(st.binary(max_size=1000))
def test_malformed_config_and_baseline(data: bytes) -> None:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "input"
        path.write_bytes(data)
        for loader in (load_config, load_baseline):
            try:
                loader(path)
            except LeakGuardError:
                pass


def test_long_line_and_nul() -> None:
    assert scan_text("a" * (1024 * 1024), "long") == []
    assert scan_text("\0anything", "nul") == []
