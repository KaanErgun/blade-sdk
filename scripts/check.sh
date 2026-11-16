#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for forbidden in .github/workflows .github/dependabot.yml .github/dependabot.yaml .gitlab-ci.yml .gitlab-ci.yaml; do
    if [ -e "$forbidden" ]; then
        printf 'Hosted CI is not allowed: %s\n' "$forbidden" >&2
        exit 1
    fi
done
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT HUP INT TERM
# Use the installed OpenSSL/zlib development libraries; no downloads or devices.
cc -std=c11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags openssl zlib) \
    native/package.c native/verify.c $(pkg-config --libs openssl zlib) -o "$build/blade-verify"
cc -std=c11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags openssl zlib) \
    native/package.c native/test.c $(pkg-config --libs openssl zlib) -o "$build/native-test"
"$build/native-test"
export BLADE_VERIFY="$build/blade-verify"
python3 -m py_compile blade_sdk.py tests/test_sdk.py tests/test_native.py
python3 -m unittest discover -s tests -v
