#!/usr/bin/env bash
set -euo pipefail

if ! command -v gpg >/dev/null 2>&1; then
  echo "SKIP: gpg not found" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/pgp-gpg-interop.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fixture="$work/fixture.txt"
message="$work/message.txt"
pubkey="$work/pubkey.asc"
signature="$work/signature.asc"
gnupg_home="$work/gnupg"

(cd "$repo_root" && moon run ./pgp/gpg_interop > "$fixture")

awk '
  /^-----BEGIN PGP INTEROP MESSAGE-----$/ { emit = 1; next }
  /^-----END PGP INTEROP MESSAGE-----$/ { emit = 0; next }
  emit { print }
' "$fixture" > "$message"

awk '
  /^-----BEGIN PGP PUBLIC KEY BLOCK-----$/ { emit = 1 }
  emit { print }
  /^-----END PGP PUBLIC KEY BLOCK-----$/ { if (emit) exit }
' "$fixture" > "$pubkey"

awk '
  /^-----BEGIN PGP SIGNATURE-----$/ { emit = 1 }
  emit { print }
  /^-----END PGP SIGNATURE-----$/ { if (emit) exit }
' "$fixture" > "$signature"

mkdir -m 700 "$gnupg_home"
gpg --batch --quiet --homedir "$gnupg_home" --import "$pubkey"

status="$work/verify.status"
stderr="$work/verify.stderr"
if ! gpg --batch --homedir "$gnupg_home" --status-fd 1 \
  --verify "$signature" "$message" > "$status" 2> "$stderr"; then
  cat "$status"
  cat "$stderr" >&2
  exit 1
fi

grep -q '^\[GNUPG:\] GOODSIG ' "$status"
grep -q '^\[GNUPG:\] VALIDSIG ' "$status"

echo "ok: gpg verified MoonBit PGP v4 Ed25519 detached signature"
