#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[timing-check-selftest] $*" >&2
  exit 1
}

fake_bin="$tmpdir/leakage_harness.exe"
cat >"$fake_bin" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

cmd="$1"
workload="$2"
samples="$3"
inner="$4"
max_abs_t="$5"

[ "$cmd" = "compare-one" ] || exit 2
[ "$samples" -ge 2 ] || exit 2
[ "$inner" -ge 1 ] || exit 2

case "$workload" in
  alpha) abs_t="0.5" ;;
  beta) abs_t="2.5" ;;
  *) exit 2 ;;
esac

printf '%s sparse_mean_us=1 dense_mean_us=1 abs_t=%s\n' "$workload" "$abs_t"
printf 'sink=1\n'
awk -v got="$abs_t" -v max="$max_abs_t" 'BEGIN { exit(got <= max ? 0 : 1) }'
SH
chmod +x "$fake_bin"

thresholds="$tmpdir/thresholds.tsv"
cat >"$thresholds" <<'EOF'
# workload max_abs_t
alpha 1.0
beta 3.0
EOF

report="$tmpdir/report.tsv"
LEAKAGE_TIMING_BIN="$fake_bin" \
  LEAKAGE_TIMING_WORKLOADS="alpha beta" \
  LEAKAGE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_TIMING_REPORT="$report" \
  bash "$ROOT/leakage_harness/timing_check.sh"

rows="$(awk 'END { print NR }' "$report")"
[ "$rows" -eq 3 ] || fail "expected header + 2 rows, got $rows"

awk '
  BEGIN { found = 0 }
  $1 == "native" && $2 == "beta" && $3 == "2.5" && $4 == "3.0" && $5 == "pass" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$report" || fail "beta threshold/report row was not recorded"

set +e
LEAKAGE_TIMING_BIN="$fake_bin" \
  LEAKAGE_TIMING_WORKLOADS="beta" \
  LEAKAGE_TIMING_MAX_ABS_T="1.0" \
  bash "$ROOT/leakage_harness/timing_check.sh" >/dev/null 2>&1
rc="$?"
set -e
[ "$rc" -eq 1 ] || fail "expected threshold failure exit 1, got $rc"

set +e
LEAKAGE_TIMING_BIN="$fake_bin" \
  LEAKAGE_TIMING_SAMPLES="0" \
  LEAKAGE_TIMING_WORKLOADS="alpha" \
  bash "$ROOT/leakage_harness/timing_check.sh" >/dev/null 2>&1
rc="$?"
set -e
[ "$rc" -eq 2 ] || fail "expected invalid samples exit 2, got $rc"

fake_moon_dir="$tmpdir/bin"
mkdir -p "$fake_moon_dir"
cat >"$fake_moon_dir/moon" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

cmd="$1"
shift

case "$cmd" in
  build)
    [ "$1" = "--target" ] || exit 2
    [ "$2" = "js" ] || exit 2
    [ "$3" = "./leakage_harness" ] || exit 2
    ;;
  run)
    [ "$1" = "--target" ] || exit 2
    [ "$2" = "js" ] || exit 2
    [ "$3" = "./leakage_harness" ] || exit 2
    [ "$4" = "--" ] || exit 2
    shift 4
    "$LEAKAGE_TIMING_FAKE_BIN" "$@"
    ;;
  *)
    exit 2
    ;;
esac
SH
chmod +x "$fake_moon_dir/moon"

js_report="$tmpdir/js-report.tsv"
PATH="$fake_moon_dir:$PATH" \
  LEAKAGE_TIMING_FAKE_BIN="$fake_bin" \
  LEAKAGE_TIMING_TARGET="js" \
  LEAKAGE_TIMING_WORKLOADS="alpha" \
  LEAKAGE_TIMING_REPORT="$js_report" \
  bash "$ROOT/leakage_harness/timing_check.sh" >/dev/null

awk '
  BEGIN { found = 0 }
  $1 == "js" && $2 == "alpha" && $5 == "pass" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$js_report" || fail "js target report row was not recorded"

echo "[timing-check-selftest] ok"
