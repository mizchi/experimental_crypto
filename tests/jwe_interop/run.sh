#!/usr/bin/env bash
# JWE interop (both directions) via Node's built-in crypto (RSA-OAEP-256 +
# AES-GCM). SKIPs (exit 0) when node / moon are absent.
set -euo pipefail

command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/jwe_interop/driver.mjs"
echo "jwe interop: PASS"
