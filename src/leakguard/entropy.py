"""Bounded base64/hex token candidates and Shannon entropy."""

import math
import re
from collections import Counter

TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{20,256}(?![A-Za-z0-9+/=_-])")
HEX = re.compile(r"[0-9a-fA-F]+\Z")


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character; empty input scores zero."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def high_entropy(text: str, threshold: float = 4.5) -> list[tuple[int, str]]:
    """Return offsets and suspicious tokens; hex uses a scaled threshold.

    Hex has at most four bits per character, compared with six for base64.
    Candidates must contain both letters and digits to reduce prose matches.
    """
    results: list[tuple[int, str]] = []
    for match in TOKEN.finditer(text):
        value = match.group()
        if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
            continue
        limit = threshold * 0.75 if HEX.fullmatch(value) else threshold
        if shannon_entropy(value) >= limit:
            results.append((match.start(), value))
    return results

