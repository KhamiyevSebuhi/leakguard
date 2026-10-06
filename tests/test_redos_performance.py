"""Generous wall-clock checks for bounded regexes and whole-file scanning."""

import time

import pytest

from leakguard.rules import RULES, Rule
from leakguard.scanner import scan_text


@pytest.mark.perf
@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_regex_adversarial(rule: Rule) -> None:
    start = time.monotonic()
    for value in ("a" * 100000, "\"='-" * 25000, "-" * 100000, "password = " + "a" * 100000):
        list(rule.regex.finditer(value))
    assert time.monotonic() - start < 5.0


@pytest.mark.perf
def test_ten_thousand_lines() -> None:
    text = "ordinary harmless source line\n" * 10000
    start = time.monotonic()
    assert scan_text(text, "large.txt") == []
    assert time.monotonic() - start < 8.0
