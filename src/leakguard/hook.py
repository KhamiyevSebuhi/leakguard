"""Install identifiable pre-commit hooks without deleting foreign hooks."""

import shlex
import sys
from pathlib import Path

from leakguard.errors import GitError
from leakguard.gitutils import git

MARKER = "# Managed by LeakGuard v1"


def hook_script(python: str | None = None) -> str:
    """Use this installation's absolute interpreter, quoted for Git's POSIX shell."""
    executable = python or sys.executable
    return (
        "#!/bin/sh\n"
        + MARKER
        + "\nexec "
        + shlex.quote(executable.replace("\\", "/"))
        + " -I -m leakguard scan --staged\n"
    )


def hook_path(root: Path) -> Path:
    """Honor Git's hooks path, including worktrees and core.hooksPath."""
    value = Path(git(root, "rev-parse", "--git-path", "hooks/pre-commit").decode("utf-8").strip())
    return value if value.is_absolute() else root / value


def _owned(content: str) -> bool:
    lines = content.splitlines()
    return (
        len(lines) == 3
        and lines[:2] == ["#!/bin/sh", MARKER]
        and lines[2].startswith("exec ")
        and lines[2].endswith(" -m leakguard scan --staged")
    )


def install(root: Path, *, force: bool = False) -> Path:
    """Create an executable hook; force explicitly permits foreign replacement."""
    path = hook_path(root)
    try:
        if path.is_symlink():
            raise GitError("Refusing to replace a symlinked hook.")
        if path.exists() and not _owned(path.read_text(encoding="utf-8")) and not force:
            raise GitError("Existing foreign hook; use --force to replace it.")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(hook_script(), encoding="utf-8", newline="\n")
        path.chmod(path.stat().st_mode | 0o111)
    except (OSError, UnicodeError):
        raise GitError("Cannot install pre-commit hook.") from None
    return path


def uninstall(root: Path) -> bool:
    """Remove only a recognized LeakGuard hook; return false if absent."""
    path = hook_path(root)
    try:
        if path.is_symlink():
            raise GitError("Refusing to remove a symlinked hook.")
        if not path.exists():
            return False
        if not _owned(path.read_text(encoding="utf-8")):
            raise GitError("Refusing to remove a foreign hook.")
        path.unlink()
    except (OSError, UnicodeError):
        raise GitError("Cannot uninstall pre-commit hook.") from None
    return True
