"""Exception taxonomy."""

from leakguard.errors import BaselineError, ConfigError, GitError, LeakGuardError


def test_taxonomy() -> None:
    for cls in (BaselineError, ConfigError, GitError):
        assert isinstance(cls("safe message"), LeakGuardError)
