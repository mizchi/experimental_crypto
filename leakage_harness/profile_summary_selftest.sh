#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[profile-summary-selftest] $*" >&2
  exit 1
}

timing_a="$tmpdir/timing-a.tsv"
cat >"$timing_a" <<'EOF'
target	workload	trials	samples	inner	max_abs_t	max_mean_abs_t	max_failures	observed_max_abs_t	mean_abs_t	failures	result
native	alpha	3	8	1	20.0	10.0	0	1.5	0.7	0	pass
native	beta	3	8	1	20.0	10.0	0	2.5	1.2	0	pass
EOF

timing_b="$tmpdir/timing-b.tsv"
cat >"$timing_b" <<'EOF'
target	workload	trials	samples	inner	max_abs_t	max_mean_abs_t	max_failures	observed_max_abs_t	mean_abs_t	failures	result
native	alpha	3	8	1	20.0	10.0	0	3.5	1.7	1	fail
js	alpha	1	2	1	100.0	100.0	0	4.0	4.0	0	pass
EOF

callgrind="$tmpdir/callgrind.tsv"
cat >"$callgrind" <<'EOF'
workload	sparse_ir	dense_ir	delta_pct	max_delta_pct	result
alpha	1000	1010	0.990000	1.0	pass
alpha	1000	1020	1.960000	2.0	pass
EOF

dudect="$tmpdir/dudect.tsv"
cat >"$dudect" <<'EOF'
target	workload	trials	measurements	rounds	max_abs_t	max_mean_abs_t	max_failures	observed_max_abs_t	mean_abs_t	failures	result
native	alpha	3	1024	1	20.0	10.0	0	1.25	0.75	0	pass
native	alpha	3	1024	1	20.0	10.0	0	2.75	1.75	1	fail
EOF

summary="$tmpdir/summary.tsv"
bash "$ROOT/leakage_harness/profile_summary.sh" "$timing_a" "$timing_b" "$callgrind" "$dudect" >"$summary"

awk -F '\t' '
  BEGIN { found = 0 }
  $1 == "timing" && $2 == "native" && $3 == "alpha" && $4 == "2" && $5 == "3.5" && $6 == "1.7" && $7 == "1" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$summary" || fail "native alpha timing aggregate missing"

awk -F '\t' '
  BEGIN { found = 0 }
  $1 == "timing" && $2 == "js" && $3 == "alpha" && $4 == "1" && $5 == "4" && $6 == "4" && $7 == "0" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$summary" || fail "js alpha timing aggregate missing"

awk -F '\t' '
  BEGIN { found = 0 }
  $1 == "callgrind" && $2 == "native" && $3 == "alpha" && $4 == "2" && $8 == "1.96" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$summary" || fail "callgrind aggregate missing"

awk -F '\t' '
  BEGIN { found = 0 }
  $1 == "dudect" && $2 == "native" && $3 == "alpha" && $4 == "2" && $5 == "2.75" && $6 == "1.75" && $7 == "1" { found = 1 }
  END { exit(found ? 0 : 1) }
' "$summary" || fail "dudect aggregate missing"

echo "[profile-summary-selftest] ok"
