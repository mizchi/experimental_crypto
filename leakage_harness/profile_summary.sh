#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: leakage_harness/profile_summary.sh <timing-or-callgrind-report.tsv>..." >&2
  exit 2
fi

printf 'kind\ttarget\tworkload\truns\tmax_observed_abs_t\tmax_mean_abs_t\tmax_failures\tmax_delta_pct\n'
awk -F '\t' '
  function max_value(old, value) {
    value += 0
    if (old == "" || value > old) {
      return value
    }
    return old
  }

  FNR == 1 && $0 == "target\tworkload\ttrials\tsamples\tinner\tmax_abs_t\tmax_mean_abs_t\tmax_failures\tobserved_max_abs_t\tmean_abs_t\tfailures\tresult" {
    kind = "timing"
    next
  }

  FNR == 1 && $0 == "target\tworkload\tabs_t\tmax_abs_t\tresult" {
    kind = "timing_old"
    next
  }

  FNR == 1 && $0 == "workload\tsparse_ir\tdense_ir\tdelta_pct\tmax_delta_pct\tresult" {
    kind = "callgrind"
    next
  }

  /^[[:space:]]*($|#)/ {
    next
  }

  kind == "timing" && NF >= 12 {
    key = $1 SUBSEP $2
    timing_runs[key] += 1
    timing_max_abs[key] = max_value(timing_max_abs[key], $9)
    timing_max_mean[key] = max_value(timing_max_mean[key], $10)
    timing_max_failures[key] = max_value(timing_max_failures[key], $11)
    next
  }

  kind == "timing_old" && NF >= 5 {
    key = $1 SUBSEP $2
    timing_runs[key] += 1
    timing_max_abs[key] = max_value(timing_max_abs[key], $3)
    timing_max_mean[key] = max_value(timing_max_mean[key], $3)
    timing_max_failures[key] = max_value(timing_max_failures[key], $5 == "fail" ? 1 : 0)
    next
  }

  kind == "callgrind" && NF >= 6 {
    key = "native" SUBSEP $1
    callgrind_runs[key] += 1
    callgrind_max_delta[key] = max_value(callgrind_max_delta[key], $4)
    next
  }

  {
    printf "unrecognized profile row in %s:%d: %s\n", FILENAME, FNR, $0 > "/dev/stderr"
    exit 2
  }

  END {
    for (key in timing_runs) {
      split(key, parts, SUBSEP)
      printf "timing\t%s\t%s\t%d\t%.17g\t%.17g\t%.17g\t\n",
        parts[1], parts[2], timing_runs[key],
        timing_max_abs[key], timing_max_mean[key], timing_max_failures[key]
    }
    for (key in callgrind_runs) {
      split(key, parts, SUBSEP)
      printf "callgrind\t%s\t%s\t%d\t\t\t\t%.17g\n",
        parts[1], parts[2], callgrind_runs[key], callgrind_max_delta[key]
    }
  }
' "$@" | sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3
