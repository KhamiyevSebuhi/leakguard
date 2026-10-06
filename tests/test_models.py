"""Model and fingerprint properties."""

from hypothesis import given
from hypothesis import strategies as st

from leakguard.models import Severity, fingerprint, redact


@given(st.text())
def test_redaction(value: str) -> None:
    assert len(redact(value)) == len(value)
    assert set(redact(value)) <= {"*"}


def test_fingerprints() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert fingerprint("r", "a\\b", "v", "a  b") == fingerprint("r", "a/b", "v", "a b")
    assert fingerprint("r", "a", "v", "a") != fingerprint("r", "a", "w", "a")
