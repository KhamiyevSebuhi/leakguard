"""Strict TOML configuration with a deliberately bounded custom regex subset."""

import math
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from leakguard.errors import ConfigError
from leakguard.models import Severity
from leakguard.rules import ENTROPY_ID, RULES, Rule, credential


@dataclass(frozen=True)
class Config:
    """Validated scanner settings; size limits are in bytes."""

    disabled_rules: tuple[str, ...] = ()
    custom_rules: tuple[Rule, ...] = ()
    entropy_threshold: float = 4.5
    ignore_paths: tuple[str, ...] = ()
    max_file_size: int = 1024 * 1024


def custom_pattern(pattern: str) -> re.Pattern[str]:
    """Compile literals/classes with optional bounded repeats, no branching.

    Groups, alternation, lookaround, backreferences, and unbounded quantifiers
    are rejected. At most one repeated atom is allowed, bounded to 256.
    This narrower language prevents user-supplied catastrophic backtracking.
    """
    if not pattern or len(pattern) > 256:
        raise ConfigError("Invalid custom rule pattern.")
    token = re.compile(r"(?:\[[A-Za-z0-9_ /+=^-]{1,80}\]|[A-Za-z0-9_ :=/@-])(?:\{([0-9]{1,3})(?:,([0-9]{1,3}))?\})?")
    pos = 0
    repeats = 0
    while pos < len(pattern):
        match = token.match(pattern, pos)
        if match is None:
            raise ConfigError("Custom patterns require literals/classes and bounded repeats only.")
        if match.group(1) is not None:
            low = int(match.group(1))
            high = int(match.group(2) or low)
            repeats += 1
            if not 1 <= low <= high <= 256 or repeats > 1:
                raise ConfigError("Custom patterns allow one repeat bounded from 1 to 256.")
        pos = match.end()
    try:
        return re.compile(pattern)
    except re.error:
        raise ConfigError("Invalid custom rule pattern.") from None


def _strings(data: dict[str, object], key: str) -> tuple[str, ...]:
    values = data.get(key, [])
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ConfigError("Configuration lists must contain strings.")
    return tuple(values)


def load_config(path: Path | None = None) -> Config:
    """Load an explicit config, or use defaults when the implicit file is absent."""
    target = path if path is not None else Path(".leakguard.toml")
    try:
        raw = target.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ConfigError("Configuration exceeds the size limit.")
        data = tomllib.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        if path is None:
            return Config()
        raise ConfigError("Configuration file not found.") from None
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise ConfigError("Cannot read valid TOML configuration.") from None
    allowed = {"disabled_rules", "custom_rules", "entropy_threshold", "ignore_paths", "max_file_size"}
    if data.keys() - allowed:
        raise ConfigError("Unknown configuration option.")
    threshold = data.get("entropy_threshold", 4.5)
    size = data.get("max_file_size", 1024 * 1024)
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 < threshold <= 6:
        raise ConfigError("entropy_threshold must be finite and between 0 and 6.")
    if type(size) is not int or size <= 0:
        raise ConfigError("max_file_size must be a positive integer.")
    custom = data.get("custom_rules", [])
    if not isinstance(custom, list):
        raise ConfigError("custom_rules must be an array of tables.")
    rules: list[Rule] = []
    ids = {r.id for r in RULES} | {ENTROPY_ID}
    for item in custom:
        if not isinstance(item, dict) or set(item) != {"id", "description", "pattern", "severity"}:
            raise ConfigError("Each custom rule requires id, description, pattern and severity.")
        if not all(isinstance(value, str) for value in item.values()):
            raise ConfigError("Custom rule fields must be strings.")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item["id"]) or item["id"] in ids:
            raise ConfigError("Custom rule IDs must be unique lowercase identifiers.")
        try:
            severity = Severity[item["severity"].upper()]
        except KeyError:
            raise ConfigError("Invalid custom rule severity.") from None
        rules.append(Rule(item["id"], item["description"], custom_pattern(item["pattern"]), severity, credential))
        ids.add(item["id"])
    disabled = _strings(data, "disabled_rules")
    if set(disabled) - ids:
        raise ConfigError("Unknown disabled rule ID.")
    return Config(disabled, tuple(rules), float(threshold), _strings(data, "ignore_paths"), size)
