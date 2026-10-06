"""Synthetic examples assembled at runtime, never stored as complete tokens."""


def samples() -> dict[str, str]:
    """Build one synthetic example per detector, including entropy."""
    mixed = "Ab3dE6gH9jK2mN5p" + "Q8sT1vW4yZ7cF0iL"
    return {
        "aws-access-key": "AKIA" + "B2C3D4E5F6G7H8J9",
        "aws-secret-key": 'aws_secret_access_key = "' + (mixed + "aB7xY2zQ") + '"',
        "github-token": "ghp_" + mixed + "aB7x",
        "slack-token": "xoxb-" + "1234567890-" + mixed,
        "stripe-key": "sk_live_" + mixed,
        "google-api-key": "AIza" + mixed + "aB7",
        "jwt": "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0In0" + "." + mixed,
        "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "generic-secret": 'password = "' + ("Bicycle9!" + "River") + '"',
        "database-url": "postgres://" + "tester:" + ("Bicycle9!" + "River") + "@localhost/demo",
        "high-entropy": mixed,
    }
