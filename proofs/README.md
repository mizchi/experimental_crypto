# `mizchi/proofs` — cross-cutting model-checked primitives

Proof-carrying versions of small leaf functions that don't naturally
belong to any single library. Properties are stated as `proof_ensure` /
`proof_require` postconditions / preconditions that `moon prove`
discharges through Why3 and an SMT solver (Z3 by default; CVC5 /
Alt-Ergo are optional).

The aim is **not** to re-derive cryptographic theorems. SMT cannot prove
"this hash is collision-resistant" or "this scalar multiplication
implements the group law." What it *can* prove is concrete arithmetic,
bit, and bounds invariants on small leaf functions — the foundations
that constant-time and canonical-form code relies on.

## Where proofs live

| Style | Location | Used for |
|---|---|---|
| Per-library proof sub-package | `<lib>/<name>/` (e.g. `pem/wrap/`) | invariants that anchor a specific library's behavior |
| Cross-cutting primitives | `proofs/` (this package) | helpers that span libraries or have no concrete caller yet |

Per-library proofs are the default. `moon prove` lowers the whole
package to Why3, so any package that mentions a type the frontend can't
translate (`Array`, complex sums, `BigInt`, etc.) cannot enable proofs
package-wide. The workaround is a leaf sub-package next to the library
that exposes only the math step and is the only place that turns on
`proof-enabled`. The host library imports it like any other dep.

`pem/wrap/` demonstrates this pattern: it lives inside `pem/`, holds the
proven base64 line-wrap helper, and `pem.encode` calls it. The full
`pem` package keeps using `Array` types and stays out of the Why3
frontend.

## What is verified here (cross-cutting)

| Function | Property |
|---|---|
| `abs(x)` | result ≥ 0 ∧ (result == x ∨ result == −x) — smoke test |
| `mod_pos(a, m)` | result ∈ [0, m) for any sign of `a`, given m > 0 |
| `hex_value(c)` | valid hex char → result ∈ [0, 16) |
| `ct_select(mask, a, b)` | mask ∈ {0, 1} → branch-free select returns `a` or `b` |
| `reduce_once(a, m)` | freeze step: `0 ≤ a < 2m` → result ∈ [0, m) |

`ct_select` and `reduce_once` are the building blocks under constant-time
scalar multiplication in `@p256` / `@p384` / `@secp256k1`, and under the
planned const-time field-arithmetic rewrite in `@ed25519`.

## Per-library proof sub-packages

| Package | Property |
|---|---|
| `pem/wrap/pem_next_chunk_len` | RFC 7468 §3 strict-mode line cap; `encode`'s wrap loop never emits a line longer than 64 chars, and terminates as long as `cap > 0` |

## Setup

`moon prove` requires Why3 1.7.2 and at least one SMT solver.

### Nix (recommended)

The repo ships a `flake.nix` that pins moonbit, opam, z3, cvc5,
alt-ergo, and the OCaml build deps Why3 needs. Enter the dev shell:

```bash
nix develop --impure
```

The shell hook sets `OPAMROOT=$PWD/.opam` and auto-activates the opam
switch if one exists. First time only, install Why3 into it:

```bash
bash proofs/setup.sh
```

With `direnv` installed, the bundled `.envrc` enters the shell
automatically on `cd`.

### Manual (no nix)

```bash
brew install opam z3                   # one-time, system-wide
bash proofs/setup.sh
```

`setup.sh` initialises a project-local opam switch
(`./.opam/moonbit-crypto`) with OCaml 4.14.2 + Why3 1.7.2 + zarith, then
runs `why3 config detect` so the discovered solvers (z3, plus cvc5 /
alt-ergo if present) are registered. After that, every shell needs:

```bash
export OPAMROOT="$PWD/.opam"
eval "$(opam env --switch=moonbit-crypto --set-switch)"
```

(or use the nix devShell, which does this for you).

## Running the prover

```bash
eval "$(opam env --switch=moonbit-crypto --set-switch)"
cd proofs && moon prove
```

Output lands in `_build/verif/proofs.proof.json` with per-goal solver
attribution and step counts. A non-zero exit code means at least one
verification condition failed.

## Adding a new proof

Three rules:

1. Mark the package as proof-enabled in `moon.pkg`:

   ```pkl
   options(
     "proof-enabled": true
   )
   ```

2. Write the contract in the function signature:

   ```moonbit
   pub fn name(args) -> Ret where {
     proof_require: <Bool expression>,
     proof_ensure: result => <Bool expression>,
   } { ... }
   ```

3. Keep each clause on a single line — `proof_require` and `proof_ensure`
   bodies do not currently parse across line breaks.

For richer proofs (predicates, lemmas, abstract models), split helpers
into a sibling `*.mbtp` file. See
`https://github.com/moonbitlang/moonbit-agent-guide/tree/main/moonbit-proof`
for the full pattern.

## What is *not* checked here

Cryptographic correctness theorems (group law, hash properties, AEAD
INT-CTXT, RFC 6979 determinism modulo subgroup order, etc.) are out of
scope for `moon prove`. Those continue to be tracked through RFC test
vectors and cross-implementation comparison, not symbolic proof.
