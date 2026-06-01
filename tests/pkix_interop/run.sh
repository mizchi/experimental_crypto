#!/usr/bin/env bash
# X.509 chain interop: openssl mints a root -> intermediate -> leaf chain;
# MoonBit pkix_verify validates it (+ negative cases). SKIPs (exit 0) when
# openssl / node / moon are absent.
set -euo pipefail

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not found" >&2; exit 0; }
command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/pkix_interop/driver.mjs"
echo "pkix interop: PASS"
