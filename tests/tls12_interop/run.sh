#!/usr/bin/env bash
# Live TLS 1.2 interop: drive the MoonBit `tls12` crypto (compiled to JS)
# through a real 1-RTT ECDHE handshake against `openssl s_server -tls1_2`, for a
# matrix of cipher suites, ECDHE groups, and certificate key types, then HTTP
# GET the server's page.
#
# Mirrors tests/tls13_interop/run.sh: SKIP (exit 0) when external tooling is
# absent so the check is CI-safe on minimal images.
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
work="$(mktemp -d "${TMPDIR:-/tmp}/tls12-interop.XXXXXX")"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cd "$repo_root"

# 1. Build the JS shim the driver imports.
echo "building tls12_interop JS shim..."
moon build --target js >/dev/null

# 2. Self-signed leaves: one ECDSA P-256, one RSA-2048 (SAN/CN=localhost).
openssl ecparam -name prime256v1 -genkey -noout -out "$work/ec.key" 2>/dev/null
openssl req -new -x509 -key "$work/ec.key" -out "$work/ec.crt" -days 2 \
  -subj "/CN=localhost" 2>/dev/null
openssl genrsa -out "$work/rsa.key" 2048 2>/dev/null
openssl req -new -x509 -key "$work/rsa.key" -out "$work/rsa.crt" -days 2 \
  -subj "/CN=localhost" 2>/dev/null

port=14620
run_case() { # cert key cipher groups
  local cert="$1" key="$2" cipher="$3" groups="$4"
  port=$((port + 1))
  openssl s_server -accept "$port" -cert "$cert" -key "$key" \
    -tls1_2 -cipher "$cipher" -groups "$groups" -www -quiet \
    >"$work/srv.log" 2>&1 &
  server_pid=$!
  # Wait for the listener.
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; break; }
    sleep 0.1
  done
  echo "=== $cipher / $groups ==="
  TLS12_PORT="$port" node "$repo_root/tests/tls12_interop/client.mjs"
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

# 3. Matrix: AES-128/256-GCM x ECDSA/RSA leaf x X25519/P-256/P-384 group.
run_case "$work/ec.crt"  "$work/ec.key"  ECDHE-ECDSA-AES128-GCM-SHA256 X25519
run_case "$work/ec.crt"  "$work/ec.key"  ECDHE-ECDSA-AES256-GCM-SHA384 P-384
run_case "$work/ec.crt"  "$work/ec.key"  ECDHE-ECDSA-AES128-GCM-SHA256 P-256
run_case "$work/rsa.crt" "$work/rsa.key" ECDHE-RSA-AES128-GCM-SHA256   X25519
run_case "$work/rsa.crt" "$work/rsa.key" ECDHE-RSA-AES256-GCM-SHA384   P-256

echo "ALL TLS 1.2 interop cases passed"
