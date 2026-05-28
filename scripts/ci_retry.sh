#!/usr/bin/env bash
set -euo pipefail

max_attempts="${CI_RETRY_ATTEMPTS:-3}"
delay_seconds="${CI_RETRY_DELAY_SECONDS:-5}"

case "$max_attempts" in
  '' | *[!0-9]*)
    echo "[ci-retry] CI_RETRY_ATTEMPTS must be a positive integer: $max_attempts" >&2
    exit 2
    ;;
esac

if [ "$max_attempts" -le 0 ]; then
  echo "[ci-retry] CI_RETRY_ATTEMPTS must be a positive integer: $max_attempts" >&2
  exit 2
fi

attempt=1
while true; do
  set +e
  "$@"
  rc="$?"
  set -e

  if [ "$rc" -eq 0 ]; then
    exit 0
  fi

  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "[ci-retry] command failed after $attempt attempts: $*" >&2
    exit "$rc"
  fi

  echo "[ci-retry] command failed with $rc; retrying attempt $((attempt + 1))/$max_attempts: $*" >&2
  sleep "$delay_seconds"
  attempt=$((attempt + 1))
  delay_seconds=$((delay_seconds * 2))
done
