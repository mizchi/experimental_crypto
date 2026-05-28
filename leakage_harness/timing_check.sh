#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${LEAKAGE_TIMING_TARGET:-native}"
BIN="${LEAKAGE_TIMING_BIN:-$ROOT/_build/native/debug/build/mizchi/leakage_harness/leakage_harness.exe}"
SAMPLES="${LEAKAGE_TIMING_SAMPLES:-8}"
INNER="${LEAKAGE_TIMING_INNER:-1}"
TRIALS="${LEAKAGE_TIMING_TRIALS:-1}"
MAX_ABS_T="${LEAKAGE_TIMING_MAX_ABS_T:-1000000}"
MAX_MEAN_ABS_T="${LEAKAGE_TIMING_MAX_MEAN_ABS_T:-}"
MAX_FAILS="${LEAKAGE_TIMING_MAX_FAILS:-0}"
DEFAULT_WORKLOADS="crypto_bigint-add_mod crypto_bigint-sub_mod crypto_bigint-mul_mod crypto_bigint-pow_mod crypto_bigint-inv_mod p256-nonce-inv p384-nonce-inv secp256k1-nonce-inv x25519-diffie_hellman ed25519-sign rsa-pkcs1v15-sign jwe-rsa-oaep-decrypt p256-sign p384-sign secp256k1-sign"
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

is_nonnegative_int() {
  local value="$1"
  case "$value" in
    '' | *[!0-9]*)
      return 1
      ;;
  esac
  [ "$value" -ge 0 ]
}

is_number() {
  awk -v value="$1" 'BEGIN { exit(value + 0 == value ? 0 : 1) }'
}

float_add() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.17g\n", a + b }'
}

float_div() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.17g\n", a / b }'
}

float_max() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.17g\n", (a > b ? a : b) }'
}

float_gt() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit(a > b ? 0 : 1) }'
}

if ! is_positive_int "$SAMPLES"; then
  echo "[leakage-timing] LEAKAGE_TIMING_SAMPLES must be a positive integer: $SAMPLES" >&2
  exit 2
fi

if ! is_positive_int "$INNER"; then
  echo "[leakage-timing] LEAKAGE_TIMING_INNER must be a positive integer: $INNER" >&2
  exit 2
fi

if ! is_positive_int "$TRIALS"; then
  echo "[leakage-timing] LEAKAGE_TIMING_TRIALS must be a positive integer: $TRIALS" >&2
  exit 2
fi

if ! is_number "$MAX_ABS_T"; then
  echo "[leakage-timing] LEAKAGE_TIMING_MAX_ABS_T must be numeric: $MAX_ABS_T" >&2
  exit 2
fi

if [ -n "$MAX_MEAN_ABS_T" ] && ! is_number "$MAX_MEAN_ABS_T"; then
  echo "[leakage-timing] LEAKAGE_TIMING_MAX_MEAN_ABS_T must be numeric: $MAX_MEAN_ABS_T" >&2
  exit 2
fi

if ! is_nonnegative_int "$MAX_FAILS"; then
  echo "[leakage-timing] LEAKAGE_TIMING_MAX_FAILS must be a non-negative integer: $MAX_FAILS" >&2
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

threshold_column_for_workload() {
  local workload="$1"
  local column="$2"
  local default_value="$3"

  if [ -z "$THRESHOLDS_FILE" ]; then
    printf '%s\n' "$default_value"
    return
  fi

  awk -v workload="$workload" -v column="$column" -v default_value="$default_value" '
    /^[[:space:]]*($|#)/ { next }
    $1 == workload && !found {
      if (NF >= column) {
        print $column
      } else {
        print default_value
      }
      found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$THRESHOLDS_FILE" || printf '%s\n' "$default_value"
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
  printf 'target\tworkload\ttrials\tsamples\tinner\tmax_abs_t\tmax_mean_abs_t\tmax_failures\tobserved_max_abs_t\tmean_abs_t\tfailures\tresult\n' >"$REPORT"
fi

failed=0
for workload in "${workloads[@]}"; do
  max_abs_t="$(threshold_column_for_workload "$workload" 2 "$MAX_ABS_T")"
  if ! is_number "$max_abs_t"; then
    echo "[leakage-timing] threshold for $workload must be numeric: $max_abs_t" >&2
    exit 2
  fi
  default_max_mean_abs_t="$MAX_MEAN_ABS_T"
  if [ -z "$default_max_mean_abs_t" ]; then
    default_max_mean_abs_t="$max_abs_t"
  fi
  max_mean_abs_t="$(threshold_column_for_workload "$workload" 3 "$default_max_mean_abs_t")"
  if ! is_number "$max_mean_abs_t"; then
    echo "[leakage-timing] mean threshold for $workload must be numeric: $max_mean_abs_t" >&2
    exit 2
  fi
  max_failures="$(threshold_column_for_workload "$workload" 4 "$MAX_FAILS")"
  if ! is_nonnegative_int "$max_failures"; then
    echo "[leakage-timing] failure threshold for $workload must be a non-negative integer: $max_failures" >&2
    exit 2
  fi

  failures=0
  observed_max_abs_t=0
  sum_abs_t=0
  for ((trial = 1; trial <= TRIALS; trial++)); do
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
      echo "[leakage-timing] could not parse abs_t for $workload trial $trial" >&2
      exit 2
    }
    if ! is_number "$abs_t"; then
      echo "[leakage-timing] parsed abs_t for $workload trial $trial is not numeric: $abs_t" >&2
      exit 2
    fi
    sum_abs_t="$(float_add "$sum_abs_t" "$abs_t")"
    observed_max_abs_t="$(float_max "$observed_max_abs_t" "$abs_t")"
    trial_failed=0
    if [ "$rc" -eq 1 ]; then
      trial_failed=1
    elif [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi
    if float_gt "$abs_t" "$max_abs_t"; then
      trial_failed=1
    fi
    if [ "$trial_failed" -eq 1 ]; then
      failures=$((failures + 1))
    fi
    printf '[leakage-timing] %s trial=%s/%s abs_t=%s max_abs_t=%s result=%s\n' \
      "$TARGET/$workload" "$trial" "$TRIALS" "$abs_t" "$max_abs_t" \
      "$(if [ "$trial_failed" -eq 1 ]; then printf 'fail'; else printf 'pass'; fi)"
  done

  mean_abs_t="$(float_div "$sum_abs_t" "$TRIALS")"
  result="pass"
  if [ "$failures" -gt "$max_failures" ]; then
    failed=1
    result="fail"
  fi
  if float_gt "$mean_abs_t" "$max_mean_abs_t"; then
    failed=1
    result="fail"
  fi
  printf '[leakage-timing] %s trials=%s observed_max_abs_t=%s mean_abs_t=%s max_abs_t=%s max_mean_abs_t=%s failures=%s max_failures=%s result=%s\n' \
    "$TARGET/$workload" "$TRIALS" "$observed_max_abs_t" "$mean_abs_t" \
    "$max_abs_t" "$max_mean_abs_t" "$failures" "$max_failures" "$result"
  if [ -n "$REPORT" ]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$TARGET" "$workload" "$TRIALS" "$SAMPLES" "$INNER" "$max_abs_t" \
      "$max_mean_abs_t" "$max_failures" "$observed_max_abs_t" "$mean_abs_t" \
      "$failures" "$result" >>"$REPORT"
  fi
done

exit "$failed"
