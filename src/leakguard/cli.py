"""LeakGuard CLI: safe diagnostics and explicit exit status."""

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from leakguard import __version__
from leakguard.baseline import load_baseline, save_baseline
from leakguard.config import Config, load_config
from leakguard.errors import LeakGuardError
from leakguard.gitutils import repository_root, scan_history, scan_staged
from leakguard.hook import install, uninstall
from leakguard.ignore import Ignore, load_ignore
from leakguard.models import Finding, Severity
from leakguard.reporters import json_report, rule_catalog, sarif_report, text_report
from leakguard.scanner import scan_directory, scan_file


class SafeParser(argparse.ArgumentParser):
    """Do not echo argument values that might themselves contain credentials."""

    def error(self, message: str) -> None:
        """Replace argparse diagnostics that interpolate untrusted arguments."""
        self.exit(2, "LeakGuard: invalid arguments; use --help.\n")


def parser() -> argparse.ArgumentParser:
    """Construct the command tree and common scan options."""
    root = SafeParser(
        prog="leakguard", description="Local secret scanner; all matches are redacted."
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "scan-history"):
        command = commands.add_parser(name)
        command.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        command.add_argument(
            "--min-severity", type=str.upper, choices=tuple(s.name for s in Severity), default="LOW"
        )
        command.add_argument("--baseline", type=Path)
        command.add_argument("--config", type=Path)
        command.add_argument("--no-color", action="store_true")
        command.add_argument("--max-file-size", type=int)
        if name == "scan":
            command.add_argument("paths", nargs="*")
            command.add_argument("--staged", action="store_true")
        else:
            command.add_argument("--since")
    baseline = commands.add_parser("baseline").add_subparsers(dest="action", required=True)
    create = baseline.add_parser("create")
    create.add_argument("path", nargs="?", default=".")
    create.add_argument("--output", type=Path, default=Path(".leakguard-baseline.json"))
    hook = commands.add_parser("hook").add_subparsers(dest="action", required=True)
    hook.add_parser("install").add_argument("--force", action="store_true")
    hook.add_parser("uninstall")
    commands.add_parser("rules")
    return root


def _settings(args: argparse.Namespace, root: Path) -> tuple[Config, Ignore]:
    explicit = getattr(args, "config", None)
    default = root / ".leakguard.toml"
    config = (
        load_config(explicit)
        if explicit is not None
        else load_config(default)
        if default.exists()
        else Config()
    )
    size = getattr(args, "max_file_size", None)
    if size is not None:
        if size <= 0:
            raise LeakGuardError("Maximum file size must be positive.")
        config = replace(config, max_file_size=size)
    return config, load_ignore(
        root / ".leakguardignore", config.ignore_paths + (".leakguard-baseline.json",)
    )


def _files(paths: list[str], root: Path, config: Config, ignore: Ignore) -> list[Finding]:
    findings: list[Finding] = []
    for value in paths:
        path = Path(value).absolute()
        base = root if path.is_relative_to(root) else path if path.is_dir() else path.parent
        if path.is_dir():
            findings.extend(scan_directory(path, config, ignore, root=base))
        else:
            findings.extend(scan_file(path, base, config, ignore))
    return list(dict.fromkeys(findings))


def _run(args: argparse.Namespace) -> int:
    if args.command == "rules":
        for row in rule_catalog():
            print(f"{row['id']:20} {row['severity']:8} {row['description']}")
        return 0
    root = Path.cwd()
    if args.command in ("hook", "scan-history") or getattr(args, "staged", False):
        root = repository_root(root)
    if args.command == "hook":
        if args.action == "install":
            install(root, force=args.force)
            print("LeakGuard hook installed.")
        else:
            removed = uninstall(root)
            print("LeakGuard hook removed." if removed else "No LeakGuard hook installed.")
        return 0
    config, ignore = _settings(args, root)
    if args.command == "baseline":
        findings = _files([args.path], root, config, ignore)
        save_baseline(args.output, {f.fingerprint for f in findings})
        print("Baseline saved (fingerprints only).")
        return 0
    if args.command == "scan-history":
        findings = scan_history(root, config, ignore, args.since)
    elif args.staged:
        if args.paths:
            raise LeakGuardError("Paths cannot be combined with --staged.")
        findings = scan_staged(root, config, ignore)
    else:
        findings = _files(args.paths or ["."], root, config, ignore)
    baseline = args.baseline
    if baseline is None and (root / ".leakguard-baseline.json").exists():
        baseline = root / ".leakguard-baseline.json"
    known = load_baseline(baseline) if baseline is not None else set()
    findings = [
        f
        for f in findings
        if f.severity >= Severity[args.min_severity] and f.fingerprint not in known
    ]
    if args.format == "json":
        report = json_report(findings)
    elif args.format == "sarif":
        report = sarif_report(findings, config.custom_rules)
    else:
        report = text_report(findings, color=sys.stdout.isatty() and not args.no_color)
    print(report, end="")
    return 1 if findings else 0


def main(argv: list[str] | None = None) -> int:
    """Return 0 for clean, 1 for findings, or 2 for usage/operational errors."""
    try:
        args = parser().parse_args(argv)
        return _run(args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except LeakGuardError as exc:
        print(f"LeakGuard: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, RuntimeError):
        print("LeakGuard: operation failed; check file access and input format.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("LeakGuard: interrupted.", file=sys.stderr)
        return 2
