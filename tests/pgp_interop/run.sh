#!/usr/bin/env bash
# OpenPGP interop (reverse): gpg signs (Ed25519 / RSA / ECDSA), MoonBit pgp
# verifies (+ tampered negatives). SKIPs (exit 0) when gpg / node / moon are
# absent. Complements pgp/gpg_interop.sh (which checks the forward direction).
set -euo pipefail

command -v gpg >/dev/null 2>&1 || { echo "SKIP: gpg not found" >&2; exit 0; }
command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/pgp_interop/driver.mjs"
echo "pgp interop: PASS"
