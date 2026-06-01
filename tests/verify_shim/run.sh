#!/usr/bin/env bash
# Reverse-direction interop: Node signs JWTs / seals AEAD; MoonBit verifies /
# decrypts (compiled to JS). Asserts valid artifacts are accepted and tampered
# ones rejected. SKIPs (exit 0) when node / moon are absent.
set -euo pipefail

command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/verify_shim/driver.mjs"
echo "verify-shim interop: PASS"
