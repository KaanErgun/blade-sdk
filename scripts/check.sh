#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for forbidden in .github/workflows .github/dependabot.yml .github/dependabot.yaml .gitlab-ci.yml .gitlab-ci.yaml; do
    if [ -e "$forbidden" ]; then
        printf 'Hosted CI is not allowed: %s\n' "$forbidden" >&2
        exit 1
    fi
done
python3 -m py_compile blade_sdk.py tests/test_sdk.py
python3 -m unittest discover -s tests -v
