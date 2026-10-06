"""Versioned, digest-only baselines with atomic replacement."""

import json
import os
import re
import tempfile
from pathlib import Path

from leakguard.errors import BaselineError


def load_baseline(path: Path) -> set[str]:
    """Load and validate a baseline without echoing its contents on error."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise BaselineError("Cannot read valid baseline JSON.") from None
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "fingerprints"}
        or type(data["version"]) is not int
        or data["version"] != 1
    ):
        raise BaselineError("Unsupported baseline schema.")
    values = data["fingerprints"]
    if not isinstance(values, list) or not all(
        isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in values
    ):
        raise BaselineError("Invalid baseline fingerprints.")
    return set(values)


def save_baseline(path: Path, fingerprints: set[str]) -> None:
    """Write sorted fingerprints atomically; never serialize source content."""
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in fingerprints):
        raise BaselineError("Invalid baseline fingerprints.")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = stream.name
            json.dump({"version": 1, "fingerprints": sorted(fingerprints)}, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    except OSError:
        raise BaselineError("Cannot save baseline.") from None
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
