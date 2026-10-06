"""Immutable public scan results and stable identifiers."""

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Ordered finding severities."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    """A result containing masked content only, never a raw secret."""

    rule_id: str
    severity: Severity
    file: str
    line: int
    column: int
    redacted_snippet: str
    fingerprint: str
    commit: str | None = None
    author: str | None = None


def redact(value: str) -> str:
    """Mask every character, preserving length without exposing short values."""
    return "*" * len(value)


def fingerprint(rule_id: str, file: str, value: str, line: str) -> str:
    """Hash rule, POSIX path, value digest, and whitespace-normalized line.

    Line numbers and commit IDs are intentionally excluded. Only the final
    digest is retained; the normalized source line is never emitted.
    """
    value_hash = hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
    payload = json.dumps([rule_id, file.replace("\\", "/"), value_hash, " ".join(line.split())])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
