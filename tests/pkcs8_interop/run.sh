#!/usr/bin/env bash
# PKCS#8 interop: openssl genpkey → MoonBit loads + signs JWT → Node verifies.
# SKIPs (exit 0) when openssl / node / moon are absent.
set -euo pipefail
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not found" >&2; exit 0; }
command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/pkcs8_interop/driver.mjs"
echo "pkcs8 interop: PASS"
