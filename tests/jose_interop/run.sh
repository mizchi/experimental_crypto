#!/usr/bin/env bash
# JOSE interop: sign JWTs with MoonBit `jwt` (+ jwk public-key export), verify
# them with Node's built-in crypto. SKIPs (exit 0) when node / moon are absent.
set -euo pipefail

command -v node >/dev/null 2>&1 || { echo "SKIP: node not found" >&2; exit 0; }
command -v moon >/dev/null 2>&1 || { echo "SKIP: moon not found" >&2; exit 0; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/jose-interop.XXXXXX")"
trap 'rm -rf "$work"' EXIT

(cd "$repo_root" && moon run ./tests/jose_interop >"$work/fixture.txt")
node "$repo_root/tests/jose_interop/verify.mjs" "$work/fixture.txt"
echo "jose interop: PASS"
