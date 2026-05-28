#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fail() {
  echo "[workload-registry-selftest] $*" >&2
  exit 1
}

sorted_words() {
  tr '[:space:]' '\n' | awk 'NF { print }' | sort -u
}

check_no_duplicates() {
  local name="$1"
  local words="$2"
  local duplicates

  duplicates="$(printf '%s\n' "$words" | tr '[:space:]' '\n' | awk 'NF { print }' | sort | uniq -d)"
  if [ -n "$duplicates" ]; then
    printf '%s\n' "$duplicates" >&2
    fail "$name has duplicate workload entries"
  fi
}

compare_words() {
  local name="$1"
  local words="$2"
  local file="$tmpdir/$name.txt"

  check_no_duplicates "$name" "$words"
  printf '%s\n' "$words" | sorted_words >"$file"
  if ! diff -u "$actual" "$file"; then
    fail "$name does not match leakage_harness list"
  fi
}

shell_default_workloads() {
  local file="$1"
  sed -n 's/^DEFAULT_WORKLOADS="\([^"]*\)".*/\1/p' "$file" | head -n 1
}

ci_callgrind_workloads() {
  sed -n 's/^[[:space:]]*LEAKAGE_CALLGRIND_WORKLOADS="\([^"]*\)" \\.*/\1/p' \
    "$ROOT/.github/workflows/ci.yml" | head -n 1
}

profile_default_workloads() {
  awk '
    /^[[:space:]]+workloads:[[:space:]]*$/ {
      in_workloads = 1
      next
    }
    in_workloads && /^[[:space:]]+default:[[:space:]]*"/ {
      line = $0
      sub(/^[[:space:]]*default:[[:space:]]*"/, "", line)
      sub(/"[[:space:]]*$/, "", line)
      print line
      found = 1
      exit
    }
    END {
      exit(found ? 0 : 1)
    }
  ' "$ROOT/.github/workflows/leakage-profile.yml"
}

threshold_workloads() {
  local file="$1"
  awk '
    /^[[:space:]]*($|#)/ { next }
    { print $1 }
  ' "$file" | sorted_words
}

actual_raw="$tmpdir/actual-raw.txt"
actual="$tmpdir/actual.txt"
moon run --target native ./leakage_harness -- list >"$actual_raw"
check_no_duplicates "leakage_harness list" "$(cat "$actual_raw")"
sorted_words <"$actual_raw" >"$actual"

compare_words "timing-check-defaults" \
  "$(shell_default_workloads "$ROOT/leakage_harness/timing_check.sh")"
compare_words "dudect-check-defaults" \
  "$(shell_default_workloads "$ROOT/leakage_harness/dudect_check.sh")"
compare_words "callgrind-check-defaults" \
  "$(shell_default_workloads "$ROOT/leakage_harness/callgrind_check.sh")"
compare_words "evidence-gate-defaults" \
  "$(shell_default_workloads "$ROOT/leakage_harness/profile_evidence_gate.sh")"
compare_words "leakage-profile-defaults" "$(profile_default_workloads)"
compare_words "ci-callgrind-workloads" "$(ci_callgrind_workloads)"

for threshold_file in \
  "$ROOT/leakage_harness/timing_smoke_thresholds.tsv" \
  "$ROOT/leakage_harness/timing_backend_smoke_thresholds.tsv" \
  "$ROOT/leakage_harness/callgrind_smoke_thresholds.tsv" \
  "$ROOT/leakage_harness/callgrind_evidence_thresholds.tsv"; do
  compare_words "$(basename "$threshold_file")" "$(threshold_workloads "$threshold_file")"
done

echo "[workload-registry-selftest] ok"
