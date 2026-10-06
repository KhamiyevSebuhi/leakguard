#!/usr/bin/env bash
# Run against a disposable repository. Never modify the caller's repository.
set -euo pipefail
PYTHON="${PYTHON:-python}"
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
cd "$workdir"
git init -q -b main
git config user.name "LeakGuard Demo"
git config user.email "demo@example.invalid"
git config commit.gpgsign false
git config core.autocrlf false

echo '=== Install hook ==='
"$PYTHON" -I -m leakguard hook install

echo '=== A synthetic credential blocks a commit ==='
"$PYTHON" -I -c 'from pathlib import Path; Path("sample.env").write_text("AKIA" + "B2C3D4E5F6G7H8J9" + "\n")'
git add sample.env
if git commit -m 'must be blocked' >commit.log 2>&1; then
  echo 'ERROR: hook allowed a secret' >&2
  exit 1
fi
cat commit.log
grep -q 'aws-access-key' commit.log
rm commit.log

echo '=== Escape hatch 1: explicit inline suppression ==='
"$PYTHON" -I -c 'from pathlib import Path; p=Path("sample.env"); p.write_text(p.read_text().strip() + " # leakguard:ignore\n")'
git add sample.env
git commit -qm 'explicitly ignored synthetic fixture'

echo '=== Escape hatch 2: reviewed fingerprint baseline ==='
"$PYTHON" -I -c 'from pathlib import Path; p=Path("sample.env"); p.write_text(p.read_text().split(" #", 1)[0] + "\n")'
"$PYTHON" -I -m leakguard baseline create
git add sample.env .leakguard-baseline.json
git commit -qm 'accept reviewed baseline'

echo '=== Removed secrets remain visible in history ==='
rm sample.env .leakguard-baseline.json
git add -u
git commit -qm 'remove synthetic credential and baseline'
set +e
"$PYTHON" -I -m leakguard scan-history --no-color
history_status=$?
"$PYTHON" -I -m leakguard scan-history --format sarif >history.sarif
sarif_status=$?
set -e
test "$history_status" -eq 1
test "$sarif_status" -eq 1
"$PYTHON" -I -c 'import json; from pathlib import Path; d=json.loads(Path("history.sarif").read_text()); assert d["version"] == "2.1.0"; assert d["runs"][0]["results"]; print("SARIF report generated and validated.")'
echo '=== Demo completed successfully ==='
