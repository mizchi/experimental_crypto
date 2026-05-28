#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[dudect-check-selftest] $*" >&2
  exit 1
}

fake_bin="$tmpdir/leakage_harness.exe"
cat >"$fake_bin" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"
workload="$2"
max_abs_t="$5"
case "$cmd:$workload" in
  dudect-one:alpha)
    abs_t=0.75
    ;;
  dudect-one:beta)
    abs_t=2.25
    ;;
  dudect-one:gamma)
    abs_t=12.5
    ;;
  *)
    echo "unexpected command: $*" >&2
    exit 2
    ;;
esac
echo "$workload dudect_measurements=$3 dudect_rounds=$4 abs_t=$abs_t"
echo "sink=1"
awk -v abs_t="$abs_t" -v max_abs_t="$max_abs_t" 'BEGIN { exit(abs_t > max_abs_t ? 1 : 0) }'
SH
chmod +x "$fake_bin"

thresholds="$tmpdir/thresholds.tsv"
cat >"$thresholds" <<'EOF'
# workload max_abs_t max_mean_abs_t max_failures
alpha 1.0 1.0 0
beta 3.0 3.0 0
gamma 10.0 10.0 0
EOF

report="$tmpdir/report.tsv"
LEAKAGE_DUDECT_BIN="$fake_bin" \
  LEAKAGE_DUDECT_TARGET=native \
  LEAKAGE_DUDECT_WORKLOADS="alpha beta" \
  LEAKAGE_DUDECT_MEASUREMENTS=16 \
  LEAKAGE_DUDECT_ROUNDS=2 \
  LEAKAGE_DUDECT_TRIALS=2 \
  LEAKAGE_DUDECT_THRESHOLDS="$thresholds" \
  LEAKAGE_DUDECT_REPORT="$report" \
  bash "$ROOT/leakage_harness/dudect_check.sh"

awk -F '\t' '
  BEGIN { found = 0 }
  $1 == "native" && $2 == "alpha" && $3 == "2" && $4 == "16" && $5 == "2" && $9 == "0.75" && $10 == "0.75" && $11 == "0" && $12 == "pass" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$report" || fail "alpha report row missing"

LEAKAGE_DUDECT_BIN="$fake_bin" \
  LEAKAGE_DUDECT_TARGET=native \
  LEAKAGE_DUDECT_WORKLOADS="gamma" \
  LEAKAGE_DUDECT_MEASUREMENTS=16 \
  LEAKAGE_DUDECT_ROUNDS=1 \
  LEAKAGE_DUDECT_THRESHOLDS="$thresholds" \
  bash "$ROOT/leakage_harness/dudect_check.sh" >/dev/null 2>&1 &&
  fail "threshold failure passed"

LEAKAGE_DUDECT_BIN="$fake_bin" \
  LEAKAGE_DUDECT_TARGET=native \
  LEAKAGE_DUDECT_WORKLOADS="alpha" \
  LEAKAGE_DUDECT_MEASUREMENTS=0 \
  bash "$ROOT/leakage_harness/dudect_check.sh" >/dev/null 2>&1 &&
  fail "invalid measurements passed"

LEAKAGE_DUDECT_BIN="$fake_bin" \
  LEAKAGE_DUDECT_TARGET=wat \
  LEAKAGE_DUDECT_WORKLOADS="alpha" \
  bash "$ROOT/leakage_harness/dudect_check.sh" >/dev/null 2>&1 &&
  fail "invalid target passed"

LEAKAGE_DUDECT_BIN="$fake_bin" \
  LEAKAGE_DUDECT_TARGET=wasm \
  LEAKAGE_DUDECT_WORKLOADS="alpha" \
  bash "$ROOT/leakage_harness/dudect_check.sh" >/dev/null 2>&1 &&
  fail "non-native bin override passed"

echo "[dudect-check-selftest] ok"
