#!/usr/bin/env bash
set -euo pipefail

ref="${1:-$(git branch --show-current 2>/dev/null || true)}"
if [ -z "$ref" ]; then
  echo "usage: scripts/run_p521_leakage_profile.sh [git-ref]" >&2
  exit 2
fi

workloads="${P521_PROFILE_WORKLOADS:-p521-nonce-inv p521-sign}"
profile_repetitions="${P521_PROFILE_REPETITIONS:-3}"
timing_samples="${P521_PROFILE_TIMING_SAMPLES:-8}"
timing_inner="${P521_PROFILE_TIMING_INNER:-1}"
timing_trials="${P521_PROFILE_TIMING_TRIALS:-3}"
dudect_measurements="${P521_PROFILE_DUDECT_MEASUREMENTS:-256}"
dudect_rounds="${P521_PROFILE_DUDECT_ROUNDS:-1}"
dudect_trials="${P521_PROFILE_DUDECT_TRIALS:-3}"
timing_targets="${P521_PROFILE_TIMING_TARGETS:-native js wasm-gc wasm}"
dudect_targets="${P521_PROFILE_DUDECT_TARGETS:-wasm-gc wasm}"
iters="${P521_PROFILE_CALLGRIND_ITERS:-1}"

cmd=(
  gh workflow run "Leakage Profile"
  --ref "$ref"
  -f "workloads=$workloads"
  -f "profile_repetitions=$profile_repetitions"
  -f "timing_samples=$timing_samples"
  -f "timing_inner=$timing_inner"
  -f "timing_trials=$timing_trials"
  -f "timing_targets=$timing_targets"
  -f "dudect_measurements=$dudect_measurements"
  -f "dudect_rounds=$dudect_rounds"
  -f "dudect_trials=$dudect_trials"
  -f "dudect_targets=$dudect_targets"
  -f "iters=$iters"
  -f "evidence_gate=true"
)

if [ "${DRY_RUN:-0}" = "1" ]; then
  printf '[p521-leakage-profile] '
  printf '%q ' "${cmd[@]}"
  printf '\n'
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "[p521-leakage-profile] gh is required" >&2
  exit 127
fi

"${cmd[@]}"
echo "[p521-leakage-profile] dispatched Leakage Profile for ref=$ref workloads=$workloads"
