#!/usr/bin/env bash
# Live TLS 1.3 interop: drive the MoonBit tls13 client (compiled to JS) through
# a real 1-RTT handshake against `openssl s_server`, then HTTP GET its page.
#
# Mirrors pgp/gpg_interop.sh: SKIP (exit 0) when the external tooling is absent
# so the check is CI-safe on minimal images.
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP: openssl not found" >&2
  exit 0
fi
if ! command -v node >/dev/null 2>&1; then
  echo "SKIP: node not found" >&2
  exit 0
fi
if ! command -v moon >/dev/null 2>&1; then
  echo "SKIP: moon not found" >&2
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/tls13-interop.XXXXXX")"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# 1. Self-signed ECDSA P-256 leaf (CertificateVerify uses ecdsa_secp256r1_sha256).
openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem" 2>/dev/null
openssl req -new -x509 -key "$work/key.pem" -out "$work/cert.pem" -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null

# 2. Compile the MoonBit interop shim (+ tls13/x25519 deps) to JS.
(cd "$repo_root" && moon build --target js >/dev/null 2>&1)

# Run one handshake against a fresh s_server keyed to a single cipher suite.
# Args: <openssl-suite-name> <client-suite-u16>
run_suite() {
  local osuite="$1" usuite="$2"

  local port=0
  for _ in $(seq 1 20); do
    cand=$((40000 + RANDOM % 20000))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$cand") 2>/dev/null; then
      port=$cand
      break
    fi
  done
  [ "$port" -ne 0 ] || { echo "FAIL: no free port" >&2; exit 1; }

  openssl s_server -tls1_3 \
    -ciphersuites "$osuite" \
    -groups X25519 \
    -cert "$work/cert.pem" -key "$work/key.pem" \
    -accept "127.0.0.1:$port" -www -quiet \
    >"$work/server.log" 2>&1 &
  server_pid=$!

  local ready=0
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then ready=1; break; fi
    sleep 0.1
  done
  [ "$ready" -eq 1 ] || { echo "FAIL: s_server did not come up" >&2; cat "$work/server.log" >&2; exit 1; }

  echo "── suite $osuite ($usuite) ─────────────────────────────"
  node "$repo_root/interop/tls_client/client.mjs" 127.0.0.1 "$port" localhost "$usuite"

  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

# 3-5. Exercise each TLS 1.3 cipher suite the client supports (u16 in decimal:
# 0x1301=4865, 0x1302=4866, 0x1303=4867) against a local openssl s_server.
run_suite TLS_AES_128_GCM_SHA256       4865
run_suite TLS_AES_256_GCM_SHA384       4866
run_suite TLS_CHACHA20_POLY1305_SHA256 4867

# 6. Optional: smoke-test real public servers (needs outbound network). Off by
# default so CI on a sandboxed image stays green. Uses the leaf-key+transcript
# proof only (no chain validation), so any 1-RTT TLS 1.3 server suffices.
if [ "${TLS_INTEROP_REMOTE:-0}" = "1" ]; then
  for spec in "cloudflare.com 4865" "www.google.com 4867" "rsa4096.badssl.com 4866"; do
    set -- $spec
    echo "── remote $1 (suite $2) ────────────────────────────────"
    node "$repo_root/interop/tls_client/client.mjs" "$1" 443 "$1" "$2"
  done
fi

echo "tls13 interop: PASS"
