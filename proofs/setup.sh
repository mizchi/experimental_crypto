#!/usr/bin/env bash
# Provision a project-local opam switch with Why3 1.7.2 and Alt-Ergo, and
# emit a `proofs/why3.conf` so `moon prove --why3-config proofs/why3.conf`
# dispatches through Z3 → CVC5 → Alt-Ergo. Idempotent; safe to re-run.
#
# Inside the nix devShell (`nix develop --impure`): gcc / zlib / cvc5 / z3 /
# opam come from nix and the heavy native deps build cleanly. Outside the
# nix shell: you need brew opam + brew z3 at minimum, and the install will
# fail if your system gcc / zlib aren't visible.
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
opam install -y --assume-depexts "why3.$WHY3_VERSION" zarith alt-ergo
why3 config detect

# Regenerate proofs/why3.conf with the actually-detected solver paths +
# versions, plus a MoonBit_Auto strategy that tries Z3 → CVC5 → Alt-Ergo.
# `moon prove` defaults to a Z3-only strategy that times out on modular
# arithmetic goals; CVC5 discharges them in well under a second.

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[proofs/setup.sh] missing prover: $1 — install it (nix devShell provides z3 / cvc5; alt-ergo comes from opam above)" >&2
    return 1
  }
}

prover_version() {
  "$1" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

require z3
require cvc5
require alt-ergo

Z3=$(command -v z3)
CVC5=$(command -v cvc5)
ALT_ERGO=$(command -v alt-ergo)

Z3_V=$(prover_version z3)
CVC5_V=$(prover_version cvc5)
ALT_V=$(prover_version alt-ergo)

cat > "$REPO_ROOT/proofs/why3.conf" <<EOF
[main]
magic = 14
memlimit = 1000
running_provers_max = 4
timelimit = 30.000000

[partial_prover]
name = "Alt-Ergo"
path = "$ALT_ERGO"
version = "$ALT_V"

[partial_prover]
name = "CVC5"
path = "$CVC5"
version = "$CVC5_V"

[partial_prover]
name = "Z3"
path = "$Z3"
version = "$Z3_V"

[strategy]
code = "start:
c Z3,$Z3_V 1 1000
c CVC5,$CVC5_V 5 1000
c Alt-Ergo,$ALT_V 5 1000
t compute_specified start
t split_vc start
c Z3,$Z3_V 10 4000
c CVC5,$CVC5_V 30 4000
c Alt-Ergo,$ALT_V 30 4000
"
desc = "Multi-solver: Z3 → CVC5 → Alt-Ergo"
name = "MoonBit_Auto"
shortcut = "4"
EOF

cat <<EOM

[proofs/setup.sh] done.

Provers detected:
  Z3        $Z3_V   $Z3
  CVC5      $CVC5_V $CVC5
  Alt-Ergo  $ALT_V  $ALT_ERGO

Use the wrapper to prove a package:

    bash proofs/prove.sh <subpackage>     # e.g. aead/wrap

Or invoke moon prove directly:

    cd <subpackage>
    moon prove --why3-config $REPO_ROOT/proofs/why3.conf

(The custom config is what makes CVC5 / Alt-Ergo available; without it,
moon prove falls back to a Z3-only strategy that times out on modular-
arithmetic postconditions.)
EOM
