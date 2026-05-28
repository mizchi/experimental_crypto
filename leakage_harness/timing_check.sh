#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${LEAKAGE_TIMING_TARGET:-native}"
BIN="${LEAKAGE_TIMING_BIN:-$ROOT/_build/native/debug/build/mizchi/leakage_harness/leakage_harness.exe}"
SAMPLES="${LEAKAGE_TIMING_SAMPLES:-8}"
INNER="${LEAKAGE_TIMING_INNER:-1}"
MAX_ABS_T="${LEAKAGE_TIMING_MAX_ABS_T:-1000000}"
DEFAULT_WORKLOADS="crypto_bigint-pow_mod crypto_bigint-inv_mod rsa-pkcs1v15-sign jwe-rsa-oaep-decrypt p256-sign p384-sign secp256k1-sign"
WORKLOADS_TEXT="${LEAKAGE_TIMING_WORKLOADS:-$DEFAULT_WORKLOADS}"
THRESHOLDS_FILE="${LEAKAGE_TIMING_THRESHOLDS:-}"
REPORT="${LEAKAGE_TIMING_REPORT:-}"

is_positive_int() {
  local value="$1"
  case "$value" in
    '' | *[!0-9]*)
      return 1
      ;;
  esac
  [ "$value" -gt 0 ]
}

is_number() {
  awk -v value="$1" 'BEGIN { exit(value + 0 == value ? 0 : 1) }'
}

if ! is_positive_int "$SAMPLES"; then
  echo "[leakage-timing] LEAKAGE_TIMING_SAMPLES must be a positive integer: $SAMPLES" >&2
  exit 2
fi

if ! is_positive_int "$INNER"; then
  echo "[leakage-timing] LEAKAGE_TIMING_INNER must be a positive integer: $INNER" >&2
  exit 2
fi

if ! is_number "$MAX_ABS_T"; then
  echo "[leakage-timing] LEAKAGE_TIMING_MAX_ABS_T must be numeric: $MAX_ABS_T" >&2
  exit 2
fi

case "$TARGET" in
  native | js | wasm-gc | wasm)
    ;;
  *)
    echo "[leakage-timing] LEAKAGE_TIMING_TARGET must be native, js, wasm-gc, or wasm: $TARGET" >&2
    exit 2
    ;;
esac

if [ -n "${LEAKAGE_TIMING_BIN:-}" ] && [ "$TARGET" != "native" ]; then
  echo "[leakage-timing] LEAKAGE_TIMING_BIN is only supported with native target" >&2
  exit 2
fi

if [ -n "$THRESHOLDS_FILE" ] && [ ! -f "$THRESHOLDS_FILE" ]; then
  echo "[leakage-timing] threshold file not found: $THRESHOLDS_FILE" >&2
  exit 2
fi

if [ "$#" -gt 0 ]; then
  workloads=("$@")
else
  read -r -a workloads <<<"$WORKLOADS_TEXT"
fi

if [ "${#workloads[@]}" -eq 0 ]; then
  echo "[leakage-timing] no workloads selected" >&2
  exit 2
fi

threshold_for_workload() {
  local workload="$1"

  if [ -z "$THRESHOLDS_FILE" ]; then
    printf '%s\n' "$MAX_ABS_T"
    return
  fi

  awk -v workload="$workload" '
    /^[[:space:]]*($|#)/ { next }
    $1 == workload && !found { print $2; found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$THRESHOLDS_FILE" || printf '%s\n' "$MAX_ABS_T"
}

build_harness() {
  if [ "$TARGET" = "native" ]; then
    if [ -z "${LEAKAGE_TIMING_BIN:-}" ]; then
      moon build --target native ./leakage_harness
    elif [ ! -x "$BIN" ]; then
      moon build --target native ./leakage_harness
    fi

    if [ ! -x "$BIN" ]; then
      echo "[leakage-timing] native harness binary not found: $BIN" >&2
      exit 2
    fi
  else
    moon build --target "$TARGET" ./leakage_harness
  fi
}

run_compare_one() {
  local workload="$1"
  local max_abs_t="$2"

  if [ "$TARGET" = "native" ]; then
    "$BIN" compare-one "$workload" "$SAMPLES" "$INNER" "$max_abs_t"
  else
    moon run --target "$TARGET" ./leakage_harness -- \
      compare-one "$workload" "$SAMPLES" "$INNER" "$max_abs_t"
  fi
}

build_harness

if [ -n "$REPORT" ]; then
  mkdir -p "$(dirname "$REPORT")"
  printf 'target\tworkload\tabs_t\tmax_abs_t\tresult\n' >"$REPORT"
fi

failed=0
for workload in "${workloads[@]}"; do
  max_abs_t="$(threshold_for_workload "$workload")"
  if ! is_number "$max_abs_t"; then
    echo "[leakage-timing] threshold for $workload must be numeric: $max_abs_t" >&2
    exit 2
  fi
  set +e
  output="$(run_compare_one "$workload" "$max_abs_t" 2>&1)"
  rc="$?"
  set -e
  printf '%s\n' "$output"
  abs_t="$(printf '%s\n' "$output" | awk -F 'abs_t=' '
    /abs_t=/ {
      split($2, parts, /[[:space:]]/)
      print parts[1]
      found = 1
    }
    END { exit(found ? 0 : 1) }
  ')" || {
    echo "[leakage-timing] could not parse abs_t for $workload" >&2
    exit 2
  }
  result="pass"
  if [ "$rc" -eq 1 ]; then
    failed=1
    result="fail"
  elif [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  printf '[leakage-timing] %s abs_t=%s max_abs_t=%s result=%s\n' \
    "$TARGET/$workload" "$abs_t" "$max_abs_t" "$result"
  if [ -n "$REPORT" ]; then
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$TARGET" "$workload" "$abs_t" "$max_abs_t" "$result" >>"$REPORT"
  fi
done

exit "$failed"
