"""Entropy examples and mathematical properties."""

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from leakguard.entropy import high_entropy, shannon_entropy
from tests.fakes import samples


@given(st.text(max_size=500))
def test_entropy_bounds(value: str) -> None:
    assert -1e-12 <= shannon_entropy(value) <= math.log2(max(1, len(set(value)))) + 1e-12


def test_known_entropy() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == 1
    assert shannon_entropy("abcd") == 2
    assert shannon_entropy("aabb") == 1
    assert shannon_entropy(samples()["high-entropy"]) > shannon_entropy("a" * 32)


@pytest.mark.parametrize("value", ["a" * 30, "1234567890" * 3, "abcdefghijklmnopqrstuvwxyz", "short"])
def test_entropy_negatives(value: str) -> None:
    assert high_entropy(value) == []


def test_entropy_thresholds() -> None:
    token = samples()["high-entropy"]
    assert high_entropy("!" + token)[0] == (1, token)
    assert high_entropy(token, 6.0) == []
    hex_value = "0123456789abcdef" * 2
    assert high_entropy(hex_value) == [(0, hex_value)]
    assert high_entropy("x" * 300) == []
