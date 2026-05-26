# `mizchi/proofs` — model-checked primitives

Proof-carrying versions of small leaf functions used across the crypto
workspace. Properties are stated as `proof_ensure` / `proof_require`
postconditions / preconditions that `moon prove` discharges through
Why3 and an SMT solver (Z3 by default; CVC5 / Alt-Ergo are optional).

The aim is **not** to re-derive cryptographic theorems. SMT cannot prove
"this hash is collision-resistant" or "this scalar multiplication
implements the group law." What it *can* prove is concrete arithmetic,
bit, and bounds invariants on small leaf functions — the foundations
that constant-time and canonical-form code relies on.

## What is verified

| Function | Property |
|---|---|
| `abs(x)` | result ≥ 0 ∧ (result == x ∨ result == −x) — smoke test |
| `mod_pos(a, m)` | result ∈ [0, m) for any sign of `a`, given m > 0 |
| `hex_value(c)` | valid hex char → result ∈ [0, 16) |
| `ct_select(mask, a, b)` | mask ∈ {0, −1} → branch-free select returns `a` or `b` |

`ct_select` is the building block under constant-time scalar multiplication
in `@p256` / `@p384` / `@secp256k1`, and under the planned const-time
field-arithmetic rewrite in `@ed25519`. Proving the algebraic identity
once anchors the assumption every caller relies on.

## Setup

`moon prove` requires Why3 1.7.2 and at least one SMT solver. Z3 is
already a Homebrew formula; the rest comes through a project-local opam
switch.

```bash
brew install opam z3                   # one-time, system-wide
export OPAMROOT="$PWD/.opam"
opam init --bare --no-setup --disable-sandboxing -y
opam switch create moonbit-crypto ocaml-base-compiler.4.14.2 -y
eval "$(opam env --switch=moonbit-crypto --set-switch)"
opam install -y why3.1.7.2 zarith
why3 config detect                     # registers z3 (+ cvc5 / alt-ergo if installed)
```

Optional: install CVC5 and Alt-Ergo through opam (`opam install cvc5
alt_ergo`) for better proof coverage on quantified goals.

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
