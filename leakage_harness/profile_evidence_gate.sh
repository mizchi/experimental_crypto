#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEFAULT_WORKLOADS="crypto_bigint-add_mod crypto_bigint-sub_mod crypto_bigint-mul_mod crypto_bigint-pow_mod crypto_bigint-inv_mod p256-nonce-inv p384-nonce-inv secp256k1-nonce-inv x25519-diffie_hellman rsa-pkcs1v15-sign jwe-rsa-oaep-decrypt p256-sign p384-sign secp256k1-sign"
WORKLOADS="${LEAKAGE_EVIDENCE_WORKLOADS:-$DEFAULT_WORKLOADS}"
TIMING_TARGETS="${LEAKAGE_EVIDENCE_TIMING_TARGETS:-native js wasm-gc wasm}"
DUDECT_TARGETS="${LEAKAGE_EVIDENCE_DUDECT_TARGETS:-native}"
MIN_TIMING_RUNS="${LEAKAGE_EVIDENCE_MIN_TIMING_RUNS:-3}"
MIN_DUDECT_RUNS="${LEAKAGE_EVIDENCE_MIN_DUDECT_RUNS:-3}"
MIN_CALLGRIND_RUNS="${LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS:-3}"
REQUIRE_DUDECT="${LEAKAGE_EVIDENCE_REQUIRE_DUDECT:-1}"
REQUIRE_CALLGRIND="${LEAKAGE_EVIDENCE_REQUIRE_CALLGRIND:-1}"
MAX_TIMING_ABS_T="${LEAKAGE_EVIDENCE_MAX_TIMING_ABS_T:-20.0}"
MAX_TIMING_MEAN_ABS_T="${LEAKAGE_EVIDENCE_MAX_TIMING_MEAN_ABS_T:-10.0}"
MAX_TIMING_FAILURES="${LEAKAGE_EVIDENCE_MAX_TIMING_FAILURES:-0}"
MAX_DUDECT_ABS_T="${LEAKAGE_EVIDENCE_MAX_DUDECT_ABS_T:-20.0}"
MAX_DUDECT_MEAN_ABS_T="${LEAKAGE_EVIDENCE_MAX_DUDECT_MEAN_ABS_T:-10.0}"
MAX_DUDECT_FAILURES="${LEAKAGE_EVIDENCE_MAX_DUDECT_FAILURES:-0}"
MAX_CALLGRIND_DELTA_PCT="${LEAKAGE_EVIDENCE_MAX_CALLGRIND_DELTA_PCT:-1.0}"
TIMING_THRESHOLDS="${LEAKAGE_EVIDENCE_TIMING_THRESHOLDS:-$ROOT/leakage_harness/timing_evidence_thresholds.tsv}"
DUDECT_THRESHOLDS="${LEAKAGE_EVIDENCE_DUDECT_THRESHOLDS:-$ROOT/leakage_harness/dudect_evidence_thresholds.tsv}"
CALLGRIND_THRESHOLDS="${LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS:-$ROOT/leakage_harness/callgrind_evidence_thresholds.tsv}"

usage() {
  echo "usage: leakage_harness/profile_evidence_gate.sh <profile-summary.tsv>..." >&2
}

is_positive_integer() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -gt 0 ]
}

is_non_negative_integer() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  return 0
}

is_number() {
  awk -v value="$1" 'BEGIN {
    exit(value ~ /^[-+]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][-+]?[0-9]+)?$/ ? 0 : 1)
  }'
}

if [ "$#" -eq 0 ]; then
  usage
  exit 2
fi

if ! is_positive_integer "$MIN_TIMING_RUNS"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MIN_TIMING_RUNS must be a positive integer: $MIN_TIMING_RUNS" >&2
  exit 2
fi

if ! is_positive_integer "$MIN_DUDECT_RUNS"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MIN_DUDECT_RUNS must be a positive integer: $MIN_DUDECT_RUNS" >&2
  exit 2
fi

if ! is_positive_integer "$MIN_CALLGRIND_RUNS"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS must be a positive integer: $MIN_CALLGRIND_RUNS" >&2
  exit 2
fi

case "$REQUIRE_DUDECT" in
  0|1) ;;
  *)
    echo "[leakage-evidence] LEAKAGE_EVIDENCE_REQUIRE_DUDECT must be 0 or 1: $REQUIRE_DUDECT" >&2
    exit 2
    ;;
esac

case "$REQUIRE_CALLGRIND" in
  0|1) ;;
  *)
    echo "[leakage-evidence] LEAKAGE_EVIDENCE_REQUIRE_CALLGRIND must be 0 or 1: $REQUIRE_CALLGRIND" >&2
    exit 2
    ;;
esac

if ! is_number "$MAX_TIMING_ABS_T"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_TIMING_ABS_T must be numeric: $MAX_TIMING_ABS_T" >&2
  exit 2
fi

if ! is_number "$MAX_TIMING_MEAN_ABS_T"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_TIMING_MEAN_ABS_T must be numeric: $MAX_TIMING_MEAN_ABS_T" >&2
  exit 2
fi

if ! is_non_negative_integer "$MAX_TIMING_FAILURES"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_TIMING_FAILURES must be a non-negative integer: $MAX_TIMING_FAILURES" >&2
  exit 2
fi

if ! is_number "$MAX_DUDECT_ABS_T"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_DUDECT_ABS_T must be numeric: $MAX_DUDECT_ABS_T" >&2
  exit 2
fi

if ! is_number "$MAX_DUDECT_MEAN_ABS_T"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_DUDECT_MEAN_ABS_T must be numeric: $MAX_DUDECT_MEAN_ABS_T" >&2
  exit 2
fi

if ! is_non_negative_integer "$MAX_DUDECT_FAILURES"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_DUDECT_FAILURES must be a non-negative integer: $MAX_DUDECT_FAILURES" >&2
  exit 2
fi

if ! is_number "$MAX_CALLGRIND_DELTA_PCT"; then
  echo "[leakage-evidence] LEAKAGE_EVIDENCE_MAX_CALLGRIND_DELTA_PCT must be numeric: $MAX_CALLGRIND_DELTA_PCT" >&2
  exit 2
fi

if [ -n "$TIMING_THRESHOLDS" ] && [ ! -f "$TIMING_THRESHOLDS" ]; then
  echo "[leakage-evidence] timing threshold file not found: $TIMING_THRESHOLDS" >&2
  exit 2
fi

if [ -n "$DUDECT_THRESHOLDS" ] && [ ! -f "$DUDECT_THRESHOLDS" ]; then
  echo "[leakage-evidence] dudect threshold file not found: $DUDECT_THRESHOLDS" >&2
  exit 2
fi

if [ -n "$CALLGRIND_THRESHOLDS" ] && [ ! -f "$CALLGRIND_THRESHOLDS" ]; then
  echo "[leakage-evidence] callgrind threshold file not found: $CALLGRIND_THRESHOLDS" >&2
  exit 2
fi

awk -F '\t' \
  -v workloads="$WORKLOADS" \
  -v timing_targets="$TIMING_TARGETS" \
  -v dudect_targets="$DUDECT_TARGETS" \
  -v min_timing_runs="$MIN_TIMING_RUNS" \
  -v min_dudect_runs="$MIN_DUDECT_RUNS" \
  -v min_callgrind_runs="$MIN_CALLGRIND_RUNS" \
  -v require_dudect="$REQUIRE_DUDECT" \
  -v require_callgrind="$REQUIRE_CALLGRIND" \
  -v default_max_abs_t="$MAX_TIMING_ABS_T" \
  -v default_max_mean_abs_t="$MAX_TIMING_MEAN_ABS_T" \
  -v default_max_failures="$MAX_TIMING_FAILURES" \
  -v default_max_dudect_abs_t="$MAX_DUDECT_ABS_T" \
  -v default_max_dudect_mean_abs_t="$MAX_DUDECT_MEAN_ABS_T" \
  -v default_max_dudect_failures="$MAX_DUDECT_FAILURES" \
  -v default_max_delta_pct="$MAX_CALLGRIND_DELTA_PCT" \
  -v timing_threshold_file="$TIMING_THRESHOLDS" \
  -v dudect_threshold_file="$DUDECT_THRESHOLDS" \
  -v callgrind_threshold_file="$CALLGRIND_THRESHOLDS" '
  function fatal(message) {
    printf "[leakage-evidence] %s\n", message > "/dev/stderr"
    fatal_error = 1
    exit 2
  }

  function split_words(text, out, parts, count, i) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", text)
    if (text == "") {
      return 0
    }
    count = split(text, parts, /[[:space:]]+/)
    for (i = 1; i <= count; i++) {
      out[i] = parts[i]
    }
    return count
  }

  function is_number(value) {
    return value ~ /^[-+]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][-+]?[0-9]+)?$/
  }

  function is_non_negative_integer(value) {
    return value ~ /^[0-9]+$/
  }

  function read_timing_thresholds(path, line, fields, count, key) {
    if (path == "") {
      return
    }
    while ((getline line < path) > 0) {
      sub(/\r$/, "", line)
      if (line ~ /^[[:space:]]*($|#)/) {
        continue
      }
      count = split(line, fields, /[[:space:]]+/)
      if (count != 5) {
        fatal("invalid timing evidence threshold row in " path ": " line)
      }
      if (!is_number(fields[3]) || !is_number(fields[4]) || !is_non_negative_integer(fields[5])) {
        fatal("invalid timing evidence threshold values in " path ": " line)
      }
      key = fields[1] SUBSEP fields[2]
      timing_limit_abs[key] = fields[3] + 0
      timing_limit_mean[key] = fields[4] + 0
      timing_limit_failures[key] = fields[5] + 0
    }
    close(path)
  }

  function read_dudect_thresholds(path, line, fields, count, key) {
    if (path == "") {
      return
    }
    while ((getline line < path) > 0) {
      sub(/\r$/, "", line)
      if (line ~ /^[[:space:]]*($|#)/) {
        continue
      }
      count = split(line, fields, /[[:space:]]+/)
      if (count != 5) {
        fatal("invalid dudect evidence threshold row in " path ": " line)
      }
      if (!is_number(fields[3]) || !is_number(fields[4]) || !is_non_negative_integer(fields[5])) {
        fatal("invalid dudect evidence threshold values in " path ": " line)
      }
      key = fields[1] SUBSEP fields[2]
      dudect_limit_abs[key] = fields[3] + 0
      dudect_limit_mean[key] = fields[4] + 0
      dudect_limit_failures[key] = fields[5] + 0
    }
    close(path)
  }

  function read_callgrind_thresholds(path, line, fields, count) {
    if (path == "") {
      return
    }
    while ((getline line < path) > 0) {
      sub(/\r$/, "", line)
      if (line ~ /^[[:space:]]*($|#)/) {
        continue
      }
      count = split(line, fields, /[[:space:]]+/)
      if (count != 2) {
        fatal("invalid callgrind evidence threshold row in " path ": " line)
      }
      if (!is_number(fields[2])) {
        fatal("invalid callgrind evidence threshold value in " path ": " line)
      }
      callgrind_limit_delta[fields[1]] = fields[2] + 0
    }
    close(path)
  }

  function timing_abs_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in timing_limit_abs) {
      return timing_limit_abs[key]
    }
    key = target SUBSEP "*"
    if (key in timing_limit_abs) {
      return timing_limit_abs[key]
    }
    key = "*" SUBSEP workload
    if (key in timing_limit_abs) {
      return timing_limit_abs[key]
    }
    key = "*" SUBSEP "*"
    if (key in timing_limit_abs) {
      return timing_limit_abs[key]
    }
    return default_max_abs_t + 0
  }

  function timing_mean_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in timing_limit_mean) {
      return timing_limit_mean[key]
    }
    key = target SUBSEP "*"
    if (key in timing_limit_mean) {
      return timing_limit_mean[key]
    }
    key = "*" SUBSEP workload
    if (key in timing_limit_mean) {
      return timing_limit_mean[key]
    }
    key = "*" SUBSEP "*"
    if (key in timing_limit_mean) {
      return timing_limit_mean[key]
    }
    return default_max_mean_abs_t + 0
  }

  function timing_failures_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in timing_limit_failures) {
      return timing_limit_failures[key]
    }
    key = target SUBSEP "*"
    if (key in timing_limit_failures) {
      return timing_limit_failures[key]
    }
    key = "*" SUBSEP workload
    if (key in timing_limit_failures) {
      return timing_limit_failures[key]
    }
    key = "*" SUBSEP "*"
    if (key in timing_limit_failures) {
      return timing_limit_failures[key]
    }
    return default_max_failures + 0
  }

  function dudect_abs_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in dudect_limit_abs) {
      return dudect_limit_abs[key]
    }
    key = target SUBSEP "*"
    if (key in dudect_limit_abs) {
      return dudect_limit_abs[key]
    }
    key = "*" SUBSEP workload
    if (key in dudect_limit_abs) {
      return dudect_limit_abs[key]
    }
    key = "*" SUBSEP "*"
    if (key in dudect_limit_abs) {
      return dudect_limit_abs[key]
    }
    return default_max_dudect_abs_t + 0
  }

  function dudect_mean_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in dudect_limit_mean) {
      return dudect_limit_mean[key]
    }
    key = target SUBSEP "*"
    if (key in dudect_limit_mean) {
      return dudect_limit_mean[key]
    }
    key = "*" SUBSEP workload
    if (key in dudect_limit_mean) {
      return dudect_limit_mean[key]
    }
    key = "*" SUBSEP "*"
    if (key in dudect_limit_mean) {
      return dudect_limit_mean[key]
    }
    return default_max_dudect_mean_abs_t + 0
  }

  function dudect_failures_limit_for(target, workload, key) {
    key = target SUBSEP workload
    if (key in dudect_limit_failures) {
      return dudect_limit_failures[key]
    }
    key = target SUBSEP "*"
    if (key in dudect_limit_failures) {
      return dudect_limit_failures[key]
    }
    key = "*" SUBSEP workload
    if (key in dudect_limit_failures) {
      return dudect_limit_failures[key]
    }
    key = "*" SUBSEP "*"
    if (key in dudect_limit_failures) {
      return dudect_limit_failures[key]
    }
    return default_max_dudect_failures + 0
  }

  function callgrind_delta_limit_for(workload) {
    if (workload in callgrind_limit_delta) {
      return callgrind_limit_delta[workload]
    }
    if ("*" in callgrind_limit_delta) {
      return callgrind_limit_delta["*"]
    }
    return default_max_delta_pct + 0
  }

  function max_value(old, value) {
    value += 0
    if (old == "" || value > old) {
      return value
    }
    return old
  }

  function evidence_fail(message) {
    failures += 1
    printf "[leakage-evidence] %s\n", message > "/dev/stderr"
  }

  BEGIN {
    workload_count = split_words(workloads, workload_order)
    timing_target_count = split_words(timing_targets, timing_target_order)
    dudect_target_count = split_words(dudect_targets, dudect_target_order)
    if (workload_count == 0) {
      fatal("no evidence workloads selected")
    }
    if (timing_target_count == 0) {
      fatal("no evidence timing targets selected")
    }
    if (require_dudect == 1 && dudect_target_count == 0) {
      fatal("no evidence dudect targets selected")
    }
    read_timing_thresholds(timing_threshold_file)
    read_dudect_thresholds(dudect_threshold_file)
    read_callgrind_thresholds(callgrind_threshold_file)
  }

  FNR == 1 && $0 == "kind\ttarget\tworkload\truns\tmax_observed_abs_t\tmax_mean_abs_t\tmax_failures\tmax_delta_pct" {
    next
  }

  /^[[:space:]]*($|#)/ {
    next
  }

  $1 == "timing" && NF >= 7 {
    if (!is_non_negative_integer($4) || !is_number($5) || !is_number($6) || !is_non_negative_integer($7)) {
      fatal("invalid timing summary row in " FILENAME ":" FNR ": " $0)
    }
    key = $2 SUBSEP $3
    timing_runs[key] += $4
    timing_max_abs[key] = max_value(timing_max_abs[key], $5)
    timing_max_mean[key] = max_value(timing_max_mean[key], $6)
    timing_max_failures[key] = max_value(timing_max_failures[key], $7)
    next
  }

  $1 == "dudect" && NF >= 7 {
    if (!is_non_negative_integer($4) || !is_number($5) || !is_number($6) || !is_non_negative_integer($7)) {
      fatal("invalid dudect summary row in " FILENAME ":" FNR ": " $0)
    }
    key = $2 SUBSEP $3
    dudect_runs[key] += $4
    dudect_max_abs[key] = max_value(dudect_max_abs[key], $5)
    dudect_max_mean[key] = max_value(dudect_max_mean[key], $6)
    dudect_max_failures[key] = max_value(dudect_max_failures[key], $7)
    next
  }

  $1 == "callgrind" && NF >= 8 {
    if (!is_non_negative_integer($4) || !is_number($8)) {
      fatal("invalid callgrind summary row in " FILENAME ":" FNR ": " $0)
    }
    key = $2 SUBSEP $3
    callgrind_runs[key] += $4
    callgrind_max_delta[key] = max_value(callgrind_max_delta[key], $8)
    next
  }

  {
    fatal("unrecognized evidence summary row in " FILENAME ":" FNR ": " $0)
  }

  END {
    if (fatal_error) {
      exit 2
    }

    for (i = 1; i <= timing_target_count; i++) {
      target = timing_target_order[i]
      for (j = 1; j <= workload_count; j++) {
        workload = workload_order[j]
        key = target SUBSEP workload
        max_abs_limit = timing_abs_limit_for(target, workload)
        max_mean_limit = timing_mean_limit_for(target, workload)
        max_failures_limit = timing_failures_limit_for(target, workload)
        if (!(key in timing_runs)) {
          evidence_fail("missing timing evidence target=" target " workload=" workload)
          continue
        }
        if (timing_runs[key] < min_timing_runs) {
          evidence_fail("insufficient timing evidence target=" target " workload=" workload " runs=" timing_runs[key] " min=" min_timing_runs)
        }
        if (timing_max_abs[key] > max_abs_limit) {
          evidence_fail("timing max abs_t exceeded target=" target " workload=" workload " observed=" timing_max_abs[key] " limit=" max_abs_limit)
        }
        if (timing_max_mean[key] > max_mean_limit) {
          evidence_fail("timing mean abs_t exceeded target=" target " workload=" workload " observed=" timing_max_mean[key] " limit=" max_mean_limit)
        }
        if (timing_max_failures[key] > max_failures_limit) {
          evidence_fail("timing failure count exceeded target=" target " workload=" workload " observed=" timing_max_failures[key] " limit=" max_failures_limit)
        }
        if (timing_runs[key] >= min_timing_runs &&
            timing_max_abs[key] <= max_abs_limit &&
            timing_max_mean[key] <= max_mean_limit &&
            timing_max_failures[key] <= max_failures_limit) {
          printf "[leakage-evidence] timing target=%s workload=%s runs=%d max_abs_t=%.17g max_mean_abs_t=%.17g max_failures=%.17g pass\n",
            target, workload, timing_runs[key], timing_max_abs[key],
            timing_max_mean[key], timing_max_failures[key]
        }
      }
    }

    if (require_dudect == 1) {
      for (i = 1; i <= dudect_target_count; i++) {
        target = dudect_target_order[i]
        for (j = 1; j <= workload_count; j++) {
          workload = workload_order[j]
          key = target SUBSEP workload
          max_abs_limit = dudect_abs_limit_for(target, workload)
          max_mean_limit = dudect_mean_limit_for(target, workload)
          max_failures_limit = dudect_failures_limit_for(target, workload)
          if (!(key in dudect_runs)) {
            evidence_fail("missing dudect evidence target=" target " workload=" workload)
            continue
          }
          if (dudect_runs[key] < min_dudect_runs) {
            evidence_fail("insufficient dudect evidence target=" target " workload=" workload " runs=" dudect_runs[key] " min=" min_dudect_runs)
          }
          if (dudect_max_abs[key] > max_abs_limit) {
            evidence_fail("dudect max abs_t exceeded target=" target " workload=" workload " observed=" dudect_max_abs[key] " limit=" max_abs_limit)
          }
          if (dudect_max_mean[key] > max_mean_limit) {
            evidence_fail("dudect mean abs_t exceeded target=" target " workload=" workload " observed=" dudect_max_mean[key] " limit=" max_mean_limit)
          }
          if (dudect_max_failures[key] > max_failures_limit) {
            evidence_fail("dudect failure count exceeded target=" target " workload=" workload " observed=" dudect_max_failures[key] " limit=" max_failures_limit)
          }
          if (dudect_runs[key] >= min_dudect_runs &&
              dudect_max_abs[key] <= max_abs_limit &&
              dudect_max_mean[key] <= max_mean_limit &&
              dudect_max_failures[key] <= max_failures_limit) {
            printf "[leakage-evidence] dudect target=%s workload=%s runs=%d max_abs_t=%.17g max_mean_abs_t=%.17g max_failures=%.17g pass\n",
              target, workload, dudect_runs[key], dudect_max_abs[key],
              dudect_max_mean[key], dudect_max_failures[key]
          }
        }
      }
    } else {
      printf "[leakage-evidence] dudect requirement disabled\n"
    }

    if (require_callgrind == 1) {
      for (j = 1; j <= workload_count; j++) {
        workload = workload_order[j]
        key = "native" SUBSEP workload
        max_delta_limit = callgrind_delta_limit_for(workload)
        if (!(key in callgrind_runs)) {
          evidence_fail("missing callgrind evidence workload=" workload)
          continue
        }
        if (callgrind_runs[key] < min_callgrind_runs) {
          evidence_fail("insufficient callgrind evidence workload=" workload " runs=" callgrind_runs[key] " min=" min_callgrind_runs)
        }
        if (callgrind_max_delta[key] > max_delta_limit) {
          evidence_fail("callgrind delta exceeded workload=" workload " observed=" callgrind_max_delta[key] " limit=" max_delta_limit)
        }
        if (callgrind_runs[key] >= min_callgrind_runs &&
            callgrind_max_delta[key] <= max_delta_limit) {
          printf "[leakage-evidence] callgrind workload=%s runs=%d max_delta_pct=%.17g pass\n",
            workload, callgrind_runs[key], callgrind_max_delta[key]
        }
      }
    } else {
      printf "[leakage-evidence] callgrind requirement disabled\n"
    }

    if (failures > 0) {
      printf "[leakage-evidence] failed checks=%d\n", failures > "/dev/stderr"
      exit 1
    }

    printf "[leakage-evidence] ok\n"
  }
' "$@"
