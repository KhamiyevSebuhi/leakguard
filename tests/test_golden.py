"""Exact stable snapshots, regenerated only by explicit pytest option."""

from pathlib import Path

import pytest

from leakguard.reporters import json_report, sarif_report, text_report
from leakguard.scanner import scan_directory


@pytest.mark.parametrize("format", ["text", "json", "sarif"])
def test_golden(golden_fixture: Path, request: pytest.FixtureRequest, format: str) -> None:
    findings = scan_directory(golden_fixture)
    output = {"text": text_report, "json": json_report, "sarif": sarif_report}[format](findings)
    expected = Path(__file__).parent / "golden" / "expected" / (format + ".txt")
    if request.config.getoption("--update-golden"):
        expected.parent.mkdir(parents=True, exist_ok=True)
        expected.write_text(output, encoding="utf-8", newline="\n")
    assert output == expected.read_text(encoding="utf-8")
