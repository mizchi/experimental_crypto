#!/usr/bin/env bash
# SSHSIG interop: OpenSSH ssh-keygen -Y sign produces signatures (Ed25519 /
# ECDSA / RSA); MoonBit ssh verifies them (+ negatives). SKIPs (exit 0) when
# ssh-keygen / node / moon are absent.
set -euo pipefail

command -v ssh-keygen >/dev/null 2>&1 || { echo "SKIP: ssh-keygen not found" >&2; exit 0; }
command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)
node "$repo_root/tests/ssh_interop/driver.mjs"
echo "ssh interop: PASS"
