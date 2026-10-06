"""Positive, negative and placeholder cases for every rule."""

import pytest

from leakguard.rules import RULES, Rule, is_placeholder
from tests.fakes import samples


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_positive(rule: Rule) -> None:
    match = rule.regex.search(samples()[rule.id])
    assert match is not None
    assert rule.validator is None or rule.validator(match.group("value"))


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_negative(rule: Rule) -> None:
    assert rule.regex.search("ordinary prose with no credentials") is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "changeme",
        "example",
        "your_api_key_here",
        "xxxx",
        "<token>",
        "${VAR}",
        "{{ var }}",
        "os.environ['VALUE']",
        "os.getenv('VALUE')",
        "a" * 40,
    ],
)
def test_placeholder(value: str) -> None:
    assert is_placeholder(value)


def test_real_value() -> None:
    assert not is_placeholder("Bicycle9!" + "River")
