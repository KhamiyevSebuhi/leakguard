"""Validate GitHub-required SARIF fields without external runtime schemas."""

import json

from leakguard.reporters import sarif_report
from leakguard.scanner import scan_text
from tests.fakes import samples


def test_contract() -> None:
    findings = scan_text("\n".join(samples().values()), "a file.env")
    document = json.loads(sarif_report(findings))
    assert document["$schema"].startswith("https://")
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "LeakGuard"
    ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert run["results"]
    for result in run["results"]:
        assert result["ruleId"] in ids
        assert result["level"] in {"note", "warning", "error"}
        assert result["message"]["text"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "a%20file.env"
        assert location["region"]["startLine"] >= 1
        assert location["region"]["startColumn"] >= 1
