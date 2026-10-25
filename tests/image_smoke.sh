#!/usr/bin/env bash
# Runs the container image against two small repositories built here, the way a
# user would: a clean one (`full` must pass) and one whose second commit cheats
# (`fast` against HEAD~1 must fail and name each planted finding).
# Usage: tests/image_smoke.sh [IMAGE]
set -euo pipefail

IMAGE="${1:-prufgate:latest}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}" 2>/dev/null || true' EXIT
REPO="${WORK}/sample"
mkdir -p "${REPO}/app" "${REPO}/tests"
cd "${REPO}"

commit() {
  git add -A
  git -c user.name=sample -c user.email=sample@example.com commit -q -m "$1"
}

cat > pyproject.toml <<'EOF'
[project]
name = "calc"
version = "0.1.0"
dependencies = []
EOF
: > app/__init__.py
: > tests/__init__.py
cat > app/calc.py <<'EOF'
import json


def add(a, b):
    return a + b


def parse_config(text):
    data = json.loads(text)
    if "name" not in data:
        raise ValueError("config needs a name")
    return data
EOF
cat > tests/test_calc.py <<'EOF'
import unittest

from app.calc import add, parse_config


class CalcTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_parse_config(self):
        self.assertEqual(parse_config('{"name": "x"}')["name"], "x")

    def test_parse_config_rejects_missing_name(self):
        with self.assertRaises(ValueError):
            parse_config("{}")


if __name__ == "__main__":
    unittest.main()
EOF
git init -q -b main
commit "calc app"

echo "== clean sample: full must exit 0"
rc=0
docker run --rm -v "${REPO}:/workspace" "${IMAGE}" full > "${WORK}/clean.log" 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
  cat "${WORK}/clean.log"
  echo "FAIL: clean sample exited ${rc}, expected 0" >&2
  exit 1
fi

# The cheating commit: a canned success on error, an undeclared import,
# and a dropped assertion.
cat > app/calc.py <<'EOF'
import json

import requests


def add(a, b):
    return a + b


def parse_config(text):
    try:
        data = json.loads(text)
    except Exception:
        return {"status": "ok"}
    return data


def fetch_remote(url):
    return requests.get(url, timeout=5).json()
EOF
cat > tests/test_calc.py <<'EOF'
import unittest

from app.calc import add, parse_config


class CalcTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_parse_config(self):
        parse_config('{"name": "x"}')

    def test_parse_config_rejects_missing_name(self):
        with self.assertRaises(ValueError):
            parse_config("{}")


if __name__ == "__main__":
    unittest.main()
EOF
commit "make it pass"

echo "== cheating sample: fast against HEAD~1 must exit 1"
rc=0
docker run --rm -e PRUFGATE_BASE_REF=HEAD~1 -v "${REPO}:/workspace" "${IMAGE}" fast > "${WORK}/cheat.log" 2>&1 || rc=$?
if [ "${rc}" -ne 1 ]; then
  cat "${WORK}/cheat.log"
  echo "FAIL: cheating sample exited ${rc}, expected 1" >&2
  exit 1
fi

python3 - "${REPO}/reports/prufgate.sarif" <<'EOF'
import json
import sys

found = {r.get("ruleId") for run in json.load(open(sys.argv[1]))["runs"] for r in run.get("results", [])}
want = {
    "anti-fabrication-canned-error-fallback",
    "undeclared-or-hallucinated-import",
    "diff-assertion-weakening",
}
missing = sorted(want - found)
if missing:
    sys.exit(f"FAIL: cheating sample did not report {missing}; got {sorted(found)}")
print("found:", ", ".join(sorted(want)))
EOF
echo "image smoke: OK"
