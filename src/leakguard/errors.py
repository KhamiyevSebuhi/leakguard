"""Safe, user-facing failures; messages never include scanned content."""


class LeakGuardError(Exception):
    """Base class for expected operational failures."""


class ConfigError(LeakGuardError):
    """Configuration is unreadable or invalid."""


class GitError(LeakGuardError):
    """A Git command could not complete."""


class BaselineError(LeakGuardError):
    """A baseline cannot be read or written safely."""

