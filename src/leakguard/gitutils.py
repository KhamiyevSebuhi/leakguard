"""Git plumbing via argument arrays; never execute filters or scanned content."""

import re
import subprocess
from pathlib import Path

from leakguard.config import Config
from leakguard.errors import GitError
from leakguard.ignore import Ignore
from leakguard.models import Finding
from leakguard.scanner import SKIP_DIRS, scan_bytes, scan_text


def git(root: Path, *args: str) -> bytes:
    """Run Git with a timeout and replace potentially sensitive stderr."""
    try:
        result = subprocess.run(["git", "--no-pager", "-c", "core.quotePath=false", *args], cwd=root, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise GitError("Git is unavailable or timed out.") from None
    if result.returncode:
        raise GitError("Git operation failed; check repository and revision.")
    return result.stdout


def repository_root(path: Path) -> Path:
    """Resolve the current worktree, including linked Git worktrees."""
    return Path(git(path, "rev-parse", "--show-toplevel").decode("utf-8").strip())


def _paths(data: bytes) -> list[str]:
    return sorted({part.decode("utf-8", errors="surrogateescape") for part in data.split(b"\0") if part})


def changed_files(root: Path, since: str, until: str = "HEAD") -> list[str]:
    """List nondeleted paths changed between two verified commit revisions."""
    first = _revision(root, since)
    last = _revision(root, until)
    return _paths(git(root, "diff", "--name-only", "--no-renames", "--diff-filter=ACMT", "-z", first, last, "--"))


def _revision(root: Path, revision: str) -> str:
    return git(root, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode("ascii").strip()


def _included(path: str, ignore: Ignore) -> bool:
    return not ignore.matches(path) and not any(part in SKIP_DIRS for part in Path(path).parts) and path != ".leakguard-baseline.json"


def staged_content(root: Path, config: Config, ignore: Ignore) -> list[tuple[str, bytes]]:
    """Read changed regular blobs from the index, not the working tree."""
    names = _paths(git(root, "diff", "--cached", "--name-only", "--no-renames", "--diff-filter=ACMT", "-z", "--"))
    blobs: list[tuple[str, bytes]] = []
    for name in names:
        if not _included(name, ignore):
            continue
        entries = git(root, "ls-files", "--stage", "-z", "--", ":(literal)" + name).split(b"\0")
        for entry in filter(None, entries):
            info = entry.split(b"\t", 1)[0].split()
            mode, oid, stage = info
            if stage != b"0":
                raise GitError("Resolve index conflicts before scanning.")
            if mode not in (b"100644", b"100755"):
                continue
            object_id = oid.decode("ascii")
            if int(git(root, "cat-file", "-s", object_id)) <= config.max_file_size:
                blobs.append((name, git(root, "cat-file", "blob", object_id)))
    return blobs


def scan_staged(root: Path, config: Config, ignore: Ignore) -> list[Finding]:
    """Scan the full contents of added/modified staged regular files."""
    return [finding for name, data in staged_content(root, config, ignore) for finding in scan_bytes(data, name, config)]


def added_lines(patch: str) -> list[tuple[int, str]]:
    """Extract added lines and their new-file line numbers from unified diffs."""
    result: list[tuple[int, str]] = []
    number: int | None = None
    for line in patch.splitlines():
        hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            number = int(hunk.group(1))
        elif number is not None:
            if line.startswith("+"):
                result.append((number, line[1:]))
                number += 1
            elif line.startswith(" "):
                number += 1
    return result


def scan_history(root: Path, config: Config, ignore: Ignore, since: str | None = None) -> list[Finding]:
    """Scan every reachable commit's additions, including subsequently removed values.

    With since, scan since..HEAD (exclusive). Without it, visit all refs.
    Merge patches are compared with the first parent. No external diff or
    text conversion helpers are allowed.
    """
    revision = [_revision(root, since) + "..HEAD"] if since is not None else ["--all"]
    commits = git(root, "log", "--format=%H", *revision, "--").decode("ascii").splitlines()
    findings: list[Finding] = []
    for commit in commits:
        author = git(root, "show", "-s", "--format=%an", commit).decode("utf-8", errors="replace").strip()
        names = _paths(git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "--no-renames", "--diff-filter=ACMT", "-r", "-m", "-z", commit, "--"))
        for name in names:
            if not _included(name, ignore):
                continue
            tree = git(root, "ls-tree", "-z", commit, "--", ":(literal)" + name)
            if not tree:
                continue
            mode, kind, oid = tree.split(b"\t", 1)[0].split()
            if kind != b"blob" or mode not in (b"100644", b"100755"):
                continue
            if int(git(root, "cat-file", "-s", oid.decode("ascii"))) > config.max_file_size:
                continue
            patch = git(root, "log", "-1", "-p", "--format=", "--root", "--diff-merges=first-parent", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0", commit, "--", ":(literal)" + name)
            for number, line in added_lines(patch.decode("utf-8", errors="replace")):
                findings.extend(scan_text(line, name, config, line_offset=number - 1, commit=commit, author=author))
    return findings
