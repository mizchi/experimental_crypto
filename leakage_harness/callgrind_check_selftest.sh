#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[callgrind-check-selftest] $*" >&2
  exit 1
}

fake_bin="$tmpdir/leakage_harness.exe"
cat >"$fake_bin" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$fake_bin"

fake_valgrind_dir="$tmpdir/bin"
mkdir -p "$fake_valgrind_dir"
cat >"$fake_valgrind_dir/valgrind" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

outfile=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --callgrind-out-file=*)
      outfile="${1#*=}"
      shift
      ;;
    --quiet | --tool=* | --cache-sim=* | --branch-sim=*)
      shift
      ;;
    *)
      break
      ;;
  esac
done

if [ -z "$outfile" ]; then
  echo "missing --callgrind-out-file" >&2
  exit 2
fi

bin="$1"
cmd="$2"
workload="$3"
class="$4"
iters="$5"
"$bin" "$cmd" "$workload" "$class" "$iters" >/dev/null

case "$workload:$class" in
  alpha:sparse) summary=1000 ;;
  alpha:dense) summary=1005 ;;
  beta:sparse) summary=2000 ;;
  beta:dense) summary=2000 ;;
  *) summary=3000 ;;
esac

printf 'events: Ir\nsummary: %s\n' "$summary" >"$outfile"
SH
chmod +x "$fake_valgrind_dir/valgrind"

thresholds="$tmpdir/thresholds.tsv"
cat >"$thresholds" <<'EOF'
# workload max_delta_pct
alpha 1.0
beta 0.0
EOF

report="$tmpdir/report.tsv"
PATH="$fake_valgrind_dir:$PATH" \
  LEAKAGE_CALLGRIND_BIN="$fake_bin" \
  LEAKAGE_CALLGRIND_WORKLOADS="alpha beta" \
  LEAKAGE_CALLGRIND_THRESHOLDS="$thresholds" \
  LEAKAGE_CALLGRIND_REPORT="$report" \
  bash "$ROOT/leakage_harness/callgrind_check.sh"

rows="$(awk 'END { print NR }' "$report")"
[ "$rows" -eq 3 ] || fail "expected header + 2 rows, got $rows"

awk '
  BEGIN { found = 0 }
  $1 == "alpha" && $5 == "1.0" && $6 == "pass" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$report" || fail "alpha threshold/report row was not recorded"

set +e
PATH="$fake_valgrind_dir:$PATH" \
  LEAKAGE_CALLGRIND_BIN="$fake_bin" \
  LEAKAGE_CALLGRIND_WORKLOADS="alpha" \
  LEAKAGE_CALLGRIND_MAX_DELTA_PCT="0.1" \
  bash "$ROOT/leakage_harness/callgrind_check.sh" >/dev/null 2>&1
rc="$?"
set -e
[ "$rc" -eq 1 ] || fail "expected threshold failure exit 1, got $rc"

set +e
PATH="$fake_valgrind_dir:$PATH" \
  LEAKAGE_CALLGRIND_BIN="$fake_bin" \
  LEAKAGE_CALLGRIND_ITERS="0" \
  LEAKAGE_CALLGRIND_WORKLOADS="alpha" \
  bash "$ROOT/leakage_harness/callgrind_check.sh" >/dev/null 2>&1
rc="$?"
set -e
[ "$rc" -eq 2 ] || fail "expected invalid iters exit 2, got $rc"

echo "[callgrind-check-selftest] ok"
