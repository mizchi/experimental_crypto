#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${LEAKAGE_CALLGRIND_BIN:-$ROOT/_build/native/debug/build/mizchi/leakage_harness/leakage_harness.exe}"
ITERS="${LEAKAGE_CALLGRIND_ITERS:-1}"
MAX_DELTA_PCT="${LEAKAGE_CALLGRIND_MAX_DELTA_PCT:-5.0}"
DEFAULT_WORKLOADS="crypto_bigint-pow_mod crypto_bigint-inv_mod rsa-pkcs1v15-sign jwe-rsa-oaep-decrypt p256-sign p384-sign secp256k1-sign"
WORKLOADS_TEXT="${LEAKAGE_CALLGRIND_WORKLOADS:-$DEFAULT_WORKLOADS}"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "[leakage-callgrind] valgrind is required" >&2
  exit 2
fi

if [ ! -x "$BIN" ]; then
  moon build --target native ./leakage_harness
fi

if [ ! -x "$BIN" ]; then
  echo "[leakage-callgrind] native harness binary not found: $BIN" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if [ "$#" -gt 0 ]; then
  workloads=("$@")
else
  read -r -a workloads <<<"$WORKLOADS_TEXT"
fi

run_class() {
  local workload="$1"
  local class="$2"
  local outfile="$tmpdir/${workload}.${class}.callgrind"

  valgrind \
    --quiet \
    --tool=callgrind \
    --cache-sim=no \
    --branch-sim=no \
    --callgrind-out-file="$outfile" \
    "$BIN" run "$workload" "$class" "$ITERS" >/dev/null

  awk '
    /^summary:/ { print $2; found = 1 }
    END { if (!found) exit 1 }
  ' "$outfile"
}

pct_delta() {
  local a="$1"
  local b="$2"
  awk -v a="$a" -v b="$b" 'BEGIN {
    diff = a > b ? a - b : b - a
    max = a > b ? a : b
    if (max == 0) {
      printf "0.000000"
    } else {
      printf "%.6f", (diff * 100.0) / max
    }
  }'
}

failed=0
for workload in "${workloads[@]}"; do
  sparse_ir="$(run_class "$workload" sparse)"
  dense_ir="$(run_class "$workload" dense)"
  delta_pct="$(pct_delta "$sparse_ir" "$dense_ir")"
  printf '[leakage-callgrind] %s sparse_ir=%s dense_ir=%s delta_pct=%s max_delta_pct=%s\n' \
    "$workload" "$sparse_ir" "$dense_ir" "$delta_pct" "$MAX_DELTA_PCT"
  if ! awk -v got="$delta_pct" -v max="$MAX_DELTA_PCT" 'BEGIN { exit(got <= max ? 0 : 1) }'; then
    failed=1
  fi
done

exit "$failed"
