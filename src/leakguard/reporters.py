"""Text, JSON and SARIF serializers for already-redacted findings."""

import json
from dataclasses import asdict
from urllib.parse import quote

from leakguard import __version__
from leakguard.models import Finding, Severity
from leakguard.rules import ENTROPY_DESCRIPTION, ENTROPY_ID, RULES, Rule


def rule_catalog(custom: tuple[Rule, ...] = ()) -> list[dict[str, str]]:
    """List detector identifiers, human-readable descriptions and severity."""
    return [
        {"id": r.id, "description": r.description, "severity": r.severity.name}
        for r in (*RULES, *custom)
    ] + [{"id": ENTROPY_ID, "description": ENTROPY_DESCRIPTION, "severity": "LOW"}]


def text_report(findings: list[Finding], *, color: bool = False) -> str:
    """Render only masked values, escaping terminal control characters."""
    if not findings:
        return "No secrets found.\n"
    lines: list[str] = []
    for finding in findings:
        location = json.dumps(finding.file, ensure_ascii=True)
        context = (
            ""
            if finding.commit is None
            else f" commit={finding.commit} author={json.dumps(finding.author, ensure_ascii=True)}"
        )
        line = f"{finding.severity.name} {location}:{finding.line}:{finding.column} {finding.rule_id} {finding.redacted_snippet}{context}"
        lines.append(f"\033[31m{line}\033[0m" if color else line)
    return "\n".join(lines) + "\n"


def json_report(findings: list[Finding]) -> str:
    """Serialize safe result fields with named severities."""
    records = [{**asdict(f), "severity": f.severity.name} for f in findings]
    return json.dumps({"version": __version__, "findings": records}, indent=2) + "\n"


def sarif_report(findings: list[Finding], custom: tuple[Rule, ...] = ()) -> str:
    """Emit SARIF 2.1.0 with a complete rule catalog and relative artifact URIs."""
    rules = [
        {
            "id": row["id"],
            "shortDescription": {"text": row["description"]},
            "properties": {"severity": row["severity"]},
        }
        for row in rule_catalog(custom)
    ]
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error"
                if finding.severity >= Severity.HIGH
                else "warning"
                if finding.severity == Severity.MEDIUM
                else "note",
                "message": {"text": "Potential credential: " + finding.redacted_snippet},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": quote(finding.file.replace("\\", "/"), safe="/")
                            },
                            "region": {"startLine": finding.line, "startColumn": finding.column},
                        }
                    }
                ],
                "partialFingerprints": {"leakguard/v1": finding.fingerprint},
                "properties": {"commit": finding.commit, "author": finding.author},
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "LeakGuard", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
