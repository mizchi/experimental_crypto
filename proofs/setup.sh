#!/usr/bin/env bash
# Generate `proofs/why3.conf` from the solvers on the current PATH so
# `moon prove --why3-config proofs/why3.conf` dispatches through
# Z3 → CVC5 → Alt-Ergo. Idempotent.
#
# Inside the nix devShell (`nix develop --impure`) the four provers are
# already on PATH — this script just emits the config and exits. Outside
# nix you need why3 1.7.2 + alt-ergo + z3 + cvc5 installed by other means
# (brew opam, homebrew taps, etc.) and visible on PATH.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[proofs/setup.sh] missing: $1 — enter the nix devShell with 'nix develop --impure'" >&2
    return 1
  }
}

prover_version() {
  "$1" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

require why3
require z3
require cvc5
require alt-ergo

# Refresh Why3's prover detection cache so subsequent direct `why3 prove`
# calls have a populated ~/.why3.conf. moon prove ignores this file (it
# uses --why3-config), but it makes ad-hoc debugging via `why3 prove -P …`
# work without surprises.
rm -f "${WHY3_CONFIG:-$HOME/.why3.conf}"
why3 config detect >/dev/null 2>&1 || true

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

[proofs/setup.sh] generated proofs/why3.conf

  Why3      $(why3 --version 2>&1 | head -1 | sed 's/Why3 platform, //')
  Z3        $Z3_V   $Z3
  CVC5      $CVC5_V $CVC5
  Alt-Ergo  $ALT_V  $ALT_ERGO

Run prove via the wrapper (picks up --why3-config automatically):

    bash proofs/prove.sh                  # every wrap package + proofs/
    bash proofs/prove.sh aead/wrap        # one sub-package
EOM
