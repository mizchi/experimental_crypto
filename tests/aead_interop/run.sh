#!/usr/bin/env bash
# AEAD interop: seal with MoonBit `aead`, open + authenticate with Node's
# built-in crypto (ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM).
# SKIPs (exit 0) when node / moon are absent, mirroring pgp/gpg_interop.sh.
set -euo pipefail

command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/aead-interop.XXXXXX")"
trap 'rm -rf "$work"' EXIT

(cd "$repo_root" && moon run ./tests/aead_interop >"$work/fixture.txt")
node "$repo_root/tests/aead_interop/verify.mjs" "$work/fixture.txt"
echo "aead interop: PASS"
