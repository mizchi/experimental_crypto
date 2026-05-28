#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[profile-evidence-gate-selftest] $*" >&2
  exit 1
}

summary_good="$tmpdir/summary-good.tsv"
cat >"$summary_good" <<'EOF'
kind	target	workload	runs	max_observed_abs_t	max_mean_abs_t	max_failures	max_delta_pct
timing	native	alpha	3	7.0	2.0	0	
timing	js	alpha	3	8.0	2.5	0	
timing	wasm-gc	alpha	3	6.5	2.0	0	
timing	wasm	alpha	3	5.5	1.5	0	
timing	native	beta	3	4.0	1.0	0	
timing	js	beta	3	4.5	1.1	0	
timing	wasm-gc	beta	3	4.1	1.2	0	
timing	wasm	beta	3	4.2	1.3	0	
callgrind	native	alpha	3				0.25
callgrind	native	beta	3				0.50
EOF

thresholds="$tmpdir/timing-thresholds.tsv"
cat >"$thresholds" <<'EOF'
# target workload max_observed_abs_t max_mean_abs_t max_failures
* * 10.0 3.0 0
EOF

callgrind_thresholds="$tmpdir/callgrind-thresholds.tsv"
cat >"$callgrind_thresholds" <<'EOF'
# workload max_delta_pct
* 0.75
EOF

LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS=3 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS="$callgrind_thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_good" \
  >/dev/null

summary_missing_target="$tmpdir/summary-missing-target.tsv"
grep -v $'^timing\twasm\tbeta\t' "$summary_good" >"$summary_missing_target"
LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS=3 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS="$callgrind_thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_missing_target" \
  >/dev/null 2>&1 && fail "missing backend timing evidence passed"

summary_low_runs="$tmpdir/summary-low-runs.tsv"
sed $'s/timing\tjs\talpha\t3/timing\tjs\talpha\t2/' "$summary_good" >"$summary_low_runs"
LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS=3 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS="$callgrind_thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_low_runs" \
  >/dev/null 2>&1 && fail "low timing run count passed"

summary_high_t="$tmpdir/summary-high-t.tsv"
sed $'s/timing\twasm-gc\talpha\t3\t6.5/timing\twasm-gc\talpha\t3\t11.0/' \
  "$summary_good" >"$summary_high_t"
LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS=3 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS="$callgrind_thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_high_t" \
  >/dev/null 2>&1 && fail "high timing t-statistic passed"

summary_high_callgrind="$tmpdir/summary-high-callgrind.tsv"
sed $'s/callgrind\tnative\tbeta\t3\t\t\t\t0.50/callgrind\tnative\tbeta\t3\t\t\t\t0.90/' \
  "$summary_good" >"$summary_high_callgrind"
LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_MIN_CALLGRIND_RUNS=3 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  LEAKAGE_EVIDENCE_CALLGRIND_THRESHOLDS="$callgrind_thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_high_callgrind" \
  >/dev/null 2>&1 && fail "high callgrind delta passed"

summary_no_callgrind="$tmpdir/summary-no-callgrind.tsv"
grep -v $'^callgrind\t' "$summary_good" >"$summary_no_callgrind"
LEAKAGE_EVIDENCE_WORKLOADS="alpha beta" \
  LEAKAGE_EVIDENCE_TIMING_TARGETS="native js wasm-gc wasm" \
  LEAKAGE_EVIDENCE_MIN_TIMING_RUNS=3 \
  LEAKAGE_EVIDENCE_REQUIRE_CALLGRIND=0 \
  LEAKAGE_EVIDENCE_TIMING_THRESHOLDS="$thresholds" \
  bash "$ROOT/leakage_harness/profile_evidence_gate.sh" "$summary_no_callgrind" \
  >/dev/null

echo "[profile-evidence-gate-selftest] ok"
