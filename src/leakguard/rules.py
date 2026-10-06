"""Bounded, line-oriented credential detectors."""

import re
from collections.abc import Callable
from dataclasses import dataclass

from leakguard.models import Severity


@dataclass(frozen=True)
class Rule:
    """A detector whose named value group selects sensitive content."""

    id: str
    description: str
    regex: re.Pattern[str]
    severity: Severity
    validator: Callable[[str], bool] | None = None


def is_placeholder(value: str) -> bool:
    """Recognize explicit examples, interpolation, environment lookups and repeats."""
    clean = value.strip().strip("\"'")
    lower = clean.lower()
    return (
        not clean
        or len(set(clean)) == 1
        or lower in {"changeme", "example", "password", "secret", "test", "dummy", "none", "null"}
        or lower.startswith(("your_", "example_", "${", "{{", "<", "os.environ", "os.getenv"))
    )


def credential(value: str) -> bool:
    """Exclude placeholders from a captured credential."""
    return not is_placeholder(value)


def database_credential(value: str) -> bool:
    """Validate the password component of a captured database URL."""
    password = value.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]
    return credential(password)


RULES: tuple[Rule, ...] = (
    Rule("aws-access-key", "AWS access key ID", re.compile(r"(?<![A-Z0-9])(?P<value>(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"), Severity.HIGH, credential),
    Rule("aws-secret-key", "AWS secret key assignment", re.compile(r"(?i)\b(?:aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key|aws_secret_access_key|secret_access_key)\s{0,16}[:=]\s{0,16}[\"']?(?P<value>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), Severity.CRITICAL, credential),
    Rule("github-token", "GitHub access token", re.compile(r"\b(?P<value>(?:gh[p os]_)[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})(?![A-Za-z0-9_])".replace("p os", "pos")), Severity.CRITICAL, credential),
    Rule("slack-token", "Slack access token", re.compile(r"\b(?P<value>(?:xoxb-|xoxp-|xapp-)[A-Za-z0-9-]{10,200})(?![A-Za-z0-9-])"), Severity.HIGH, credential),
    Rule("stripe-key", "Stripe live API key", re.compile(r"\b(?P<value>(?:sk_live_|rk_live_)[A-Za-z0-9]{16,200})(?![A-Za-z0-9])"), Severity.CRITICAL, credential),
    Rule("google-api-key", "Google API key", re.compile(r"\b(?P<value>AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])"), Severity.HIGH, credential),
    Rule("jwt", "JSON Web Token", re.compile(r"\b(?P<value>eyJ[A-Za-z0-9_-]{5,509}\.[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{8,512})(?![A-Za-z0-9_.-])"), Severity.HIGH, credential),
    Rule("private-key", "PEM private key marker (including RSA, EC, OpenSSH, PGP)", re.compile(r"(?P<value>-----BEGIN (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----)"), Severity.CRITICAL),
    Rule("generic-secret", "Credential assignment", re.compile(r"(?i)\b(?:password|passwd|secret|token|api_key|apikey)\s{0,16}[:=]\s{0,16}[\"']?(?P<value>[^\s\"'`#;,]{8,256})"), Severity.MEDIUM, credential),
    Rule("database-url", "Database URL containing a password", re.compile(r"(?i)(?P<value>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]{1,128}:[^\s@]{1,256}@[^\s\"'<>]{1,256})"), Severity.HIGH, database_credential),
)

ENTROPY_ID = "high-entropy"
ENTROPY_DESCRIPTION = "High-entropy base64/hex-like string"
