"""Redaction safety across every serialization format."""

import json

import pytest

from leakguard.reporters import json_report, rule_catalog, sarif_report, text_report
from leakguard.scanner import scan_text
from tests.fakes import samples


@pytest.mark.parametrize("example", samples().values())
def test_no_secret_leaks(example: str) -> None:
    findings = scan_text(example, "sample.env")
    assert findings
    for report in (text_report(findings), json_report(findings), sarif_report(findings)):
        assert example not in report
        assert ("Bicycle9!" + "River") not in report
        assert all(set(f.redacted_snippet) <= {"*"} for f in findings)


def test_text_and_json() -> None:
    findings = scan_text(samples()["aws-access-key"], "a\nfile", commit="abc", author="A\x1bB")
    assert "\x1b" not in text_report(findings)
    assert "\x1b[31m" in text_report(findings, color=True)
    assert text_report([]) == "No secrets found.\n"
    assert json.loads(json_report(findings))["findings"][0]["severity"] == "HIGH"
    assert "commit=abc" in text_report(findings)
    assert len(rule_catalog()) == 11
