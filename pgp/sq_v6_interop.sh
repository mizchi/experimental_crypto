#!/usr/bin/env bash
set -euo pipefail

if ! command -v sq >/dev/null 2>&1; then
  echo "SKIP: sq not found" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/pgp-sq-v6-interop.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fixture="$work/fixture.txt"
message="$work/message.txt"
pubkey="$work/pubkey.asc"
signature="$work/signature.asc"

(cd "$repo_root" && moon run ./pgp/gpg_interop >"$fixture")

awk '
  /^-----BEGIN PGP V6 INTEROP MESSAGE-----$/ { emit = 1; next }
  /^-----END PGP V6 INTEROP MESSAGE-----$/ { emit = 0; next }
  emit { print }
' "$fixture" >"$message"

awk '
  /^-----BEGIN PGP V6 INTEROP PUBLIC KEY-----$/ { section = 1; next }
  section && /^-----BEGIN PGP PUBLIC KEY BLOCK-----$/ { emit = 1 }
  section && emit { print }
  section && /^-----END PGP PUBLIC KEY BLOCK-----$/ { exit }
' "$fixture" >"$pubkey"

awk '
  /^-----BEGIN PGP V6 INTEROP SIGNATURE-----$/ { section = 1; next }
  section && /^-----BEGIN PGP SIGNATURE-----$/ { emit = 1 }
  section && emit { print }
  section && /^-----END PGP SIGNATURE-----$/ { exit }
' "$fixture" >"$signature"

stdout="$work/verify.stdout"
stderr="$work/verify.stderr"
if ! sq --time 2024-01-01 verify \
  --signer-file "$pubkey" \
  --signature-file "$signature" \
  "$message" >"$stdout" 2>"$stderr"; then
  sq packet dump "$pubkey" >&2 || true
  sq packet dump "$signature" >&2 || true
  cat "$stdout"
  cat "$stderr" >&2
  exit 1
fi

cat "$stdout"
echo "ok: sq verified MoonBit PGP v6 Ed25519 detached signature"
