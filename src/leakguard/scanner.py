"""File traversal and pure text scanning; scanned code is never executed."""

import os
from pathlib import Path

from leakguard.config import Config
from leakguard.entropy import high_entropy
from leakguard.errors import LeakGuardError
from leakguard.ignore import Ignore, inline_ignored
from leakguard.models import Finding, Severity, fingerprint, redact
from leakguard.rules import ENTROPY_ID, RULES, is_placeholder

SKIP_DIRS = frozenset({".git", "node_modules", "venv", ".venv", "env", "__pycache__"})
DEFAULT_CONFIG = Config()
DEFAULT_IGNORE = Ignore()


def scan_text(
    text: str,
    file: str,
    config: Config = DEFAULT_CONFIG,
    *,
    line_offset: int = 0,
    commit: str | None = None,
    author: str | None = None,
) -> list[Finding]:
    """Scan lines deterministically, retaining only masked values and digests."""
    findings: list[Finding] = []
    if "\0" in text:
        return findings
    rules = [r for r in (*RULES, *config.custom_rules) if r.id not in config.disabled_rules]
    for number, line in enumerate(text.splitlines(), start=1 + line_offset):
        occupied: list[tuple[int, int]] = []
        for rule in rules:
            if inline_ignored(line, rule.id):
                continue
            for match in rule.regex.finditer(line):
                group = "value" if "value" in rule.regex.groupindex else 0
                value = match.group(group)
                if rule.validator is not None and not rule.validator(value):
                    continue
                start, end = match.span(group)
                occupied.append((start, end))
                findings.append(
                    Finding(
                        rule.id,
                        rule.severity,
                        file,
                        number,
                        start + 1,
                        redact(value)[:80],
                        fingerprint(rule.id, file, value, line),
                        commit,
                        author,
                    )
                )
        if ENTROPY_ID in config.disabled_rules or inline_ignored(line, ENTROPY_ID):
            continue
        for start, value in high_entropy(line, config.entropy_threshold):
            if is_placeholder(value) or any(
                start < end and start + len(value) > begin for begin, end in occupied
            ):
                continue
            findings.append(
                Finding(
                    ENTROPY_ID,
                    Severity.LOW,
                    file,
                    number,
                    start + 1,
                    redact(value)[:80],
                    fingerprint(ENTROPY_ID, file, value, line),
                    commit,
                    author,
                )
            )
    return sorted(findings, key=lambda f: (f.file, f.line, f.column, f.rule_id))


def scan_bytes(
    data: bytes,
    file: str,
    config: Config = DEFAULT_CONFIG,
    *,
    commit: str | None = None,
    author: str | None = None,
) -> list[Finding]:
    """Skip oversized/binary data; decode invalid UTF-8 conservatively."""
    if len(data) > config.max_file_size or b"\0" in data:
        return []
    return scan_text(
        data.decode("utf-8", errors="replace"), file, config, commit=commit, author=author
    )


def scan_file(
    path: Path, root: Path, config: Config = DEFAULT_CONFIG, ignore: Ignore = DEFAULT_IGNORE
) -> list[Finding]:
    """Read a bounded regular file, skipping symlinks outside the scan root."""
    try:
        resolved = path.resolve()
        root = root.resolve()
        if not resolved.is_relative_to(root):
            return []
        name = path.absolute().relative_to(root).as_posix()
        if ignore.matches(name) or any(p in SKIP_DIRS for p in Path(name).parts):
            return []
        if not path.is_file():
            raise LeakGuardError("Input is not an accessible regular file.")
        if path.stat().st_size > config.max_file_size:
            return []
        with path.open("rb") as stream:
            data = stream.read(config.max_file_size + 1)
        return scan_bytes(data, name, config)
    except (OSError, ValueError, RuntimeError):
        raise LeakGuardError("Cannot safely read input file.") from None


def scan_directory(
    path: Path,
    config: Config = DEFAULT_CONFIG,
    ignore: Ignore = DEFAULT_IGNORE,
    *,
    root: Path | None = None,
) -> list[Finding]:
    """Walk deterministically without following directory symlinks."""
    root = (root or path).resolve()
    findings: list[Finding] = []

    def on_error(error: OSError) -> None:
        raise LeakGuardError("Cannot enumerate input directory.") from error

    for current, directories, files in os.walk(path, followlinks=False, onerror=on_error):
        directories[:] = sorted(
            d
            for d in directories
            if d not in SKIP_DIRS
            and not Path(current, d).is_symlink()
            and not ignore.matches(Path(current, d).relative_to(root).as_posix() + "/")
        )
        for filename in sorted(files):
            findings.extend(scan_file(Path(current, filename), root, config, ignore))
    return findings
