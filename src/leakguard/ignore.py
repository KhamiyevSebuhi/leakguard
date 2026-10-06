"""Simple POSIX glob ignores and explicit inline suppression comments."""

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from leakguard.errors import ConfigError

INLINE = re.compile(r"(?:#|//|;|<!--)\s*leakguard:ignore(?:=([a-z0-9-]+))?(?=\s|$|-->)")


@dataclass(frozen=True)
class Ignore:
    """Root-relative glob patterns; negation and gitignore escaping are unsupported."""

    patterns: tuple[str, ...] = ()

    def matches(self, path: str) -> bool:
        """Match basenames, relative paths, and directory patterns ending in slash."""
        clean = path.replace("\\", "/").removeprefix("./")
        for pattern in self.patterns:
            pattern = pattern.removeprefix("/")
            if pattern.endswith("/"):
                directory = pattern.rstrip("/")
                parents = clean.split("/")[:-1]
                if "/" not in directory and any(fnmatch.fnmatchcase(p, directory) for p in parents):
                    return True
                if clean.startswith(directory + "/"):
                    return True
            elif fnmatch.fnmatchcase(clean, pattern) or (
                "/" not in pattern and fnmatch.fnmatchcase(clean.rsplit("/", 1)[-1], pattern)
            ):
                return True
        return False


def load_ignore(path: Path, extra: tuple[str, ...] = ()) -> Ignore:
    """Read optional ignore patterns without exposing malformed file contents."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Ignore(extra)
    except (OSError, UnicodeError):
        raise ConfigError("Cannot read ignore file.") from None
    return Ignore(
        extra
        + tuple(
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    )


def inline_ignored(line: str, rule_id: str) -> bool:
    """Suppress all rules or the named rule only when a comment marker exists."""
    return any(match.group(1) in (None, rule_id) for match in INLINE.finditer(line))
