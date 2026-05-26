#!/usr/bin/env bash
# Provision a project-local opam switch + Why3 1.7.2 so `moon prove`
# can verify the `proofs/` package. Idempotent; safe to re-run.
#
# Requires: opam, z3 (both via Homebrew or system package manager).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export OPAMROOT="$REPO_ROOT/.opam"
SWITCH=moonbit-crypto
OCAML_VERSION=4.14.2
WHY3_VERSION=1.7.2

if [ ! -d "$OPAMROOT" ]; then
  opam init --bare --no-setup --disable-sandboxing -y
fi

if ! opam switch list --short 2>/dev/null | grep -qx "$SWITCH"; then
  opam switch create "$SWITCH" "ocaml-base-compiler.$OCAML_VERSION" -y
fi

eval "$(opam env --switch="$SWITCH" --set-switch)"
opam install -y "why3.$WHY3_VERSION" zarith
why3 config detect

cat <<EOM

[proofs/setup.sh] done. To enter the proof env in a new shell:

    export OPAMROOT="$REPO_ROOT/.opam"
    eval "\$(opam env --switch=$SWITCH --set-switch)"

Then:

    cd proofs && moon prove
EOM
