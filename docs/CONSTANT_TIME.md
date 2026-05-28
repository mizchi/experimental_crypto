# Constant-Time Status

This workspace uses three different levels of side-channel language:

- **Fixed-limb** means the arithmetic operates on caller-selected fixed-width
  limb arrays instead of runtime-sized `@bigint` values.
- **Branchless / fixed-iteration intended** means the source avoids
  secret-dependent branches in the target loop and runs a fixed number of
  iterations for a fixed limb width.
- **Constant-time / constant-clock proven** is stronger: generated code has
  been checked with an external leakage harness on the relevant backend. This
  workspace does not claim that level yet.

## Current Status

| Area | Status | Remaining risk |
|---|---|---|
| `crypto_bigint` add/sub/mul | Fixed-limb, branchless-intended source loops. | No dudect / callgrind measurement yet; allocation and backend lowering are not audited. |
| `crypto_bigint` pow | Fixed exponent-width loop. Odd moduli use 32-bit-word Montgomery multiplication. | No generated-code leakage measurement yet. |
| `crypto_bigint` inv | Fixed-iteration odd-modulus almost-inverse loop. | Final invertible / non-invertible branch is caller-visible; no generated-code leakage measurement yet. |
| RSA sign / JWE RSA-OAEP decrypt | Private modexp routes through `crypto_bigint.Uint::pow_mod`. | No CRT hardening, no blinding, no external leakage measurement yet. |
| ECDSA final nonce inverse | `p256`, `p384`, and `secp256k1` route `k^-1 mod n` through `crypto_bigint.Uint::inv_mod`. | No generated-code leakage measurement yet. |
| ECDSA scalar multiplication | P-256, P-384, and secp256k1 sign-side base-point multiplication use fixed-iteration complete-addition paths. Public verify remains affine `@bigint`. | All ECDSA sign paths still need external leakage measurement. |
| Ed25519 | Still `@bigint`-backed Edwards arithmetic. | Limb rewrite pending. |
| X25519 | 10-limb Montgomery ladder with conditional swaps. | Backend-level constant-time behavior is not proven. |
| AES-GCM | AES uses table-based S-boxes. | Not constant-time on shared-cache targets. |
| ChaCha20-Poly1305 | Limb arithmetic, no AES tables. | Backend-level multiply timing and generated code are not audited. |

## Measurement Plan

The next step is to add backend-specific leakage checks instead of relying on
source inspection alone.

1. Add native dudect-style harnesses for:
   - `crypto_bigint.Uint::pow_mod` with same modulus and base, split by secret
     exponent class.
   - `crypto_bigint.Uint::inv_mod` with same modulus, split by secret input
     class.
   - RSA sign and JWE RSA-OAEP decrypt with fixed public shape and classed
     private exponent / ciphertext inputs.
2. Add callgrind-style instruction-count comparisons for the same fixed-size
   classes. These do not prove absence of microarchitectural leakage, but they
   catch obvious secret-dependent control flow and allocation deltas.
3. Add ECDSA signing leakage checks for P-256, P-384, and secp256k1.
4. Treat JavaScript timing checks as smoke tests only. JIT, GC, and BigInt
   lowering make JS unsuitable for strong constant-time claims.

`crypto_bigint/crypto_bigint_bench_test.mbt` contains sparse-vs-dense
`moon bench` inputs for `pow_mod` and `inv_mod`. `p256`, `p384`, and
`secp256k1` also contain sparse-vs-dense private-scalar sign benches. They are
useful for spotting large regressions, but they are not part of the acceptance
criteria.

`leakage_harness` is the first native measurement entry point:

```sh
moon run --target native ./leakage_harness -- list
moon run --target native ./leakage_harness -- compare 8 1
moon run --target native ./leakage_harness -- run p256-sign sparse 100
moon run --target native ./leakage_harness -- run p256-sign dense 100
bash leakage_harness/callgrind_check.sh
nix develop --impure .#leakage --command bash leakage_harness/callgrind_check.sh
LEAKAGE_CALLGRIND_THRESHOLDS=leakage_harness/callgrind_smoke_thresholds.tsv \
  LEAKAGE_CALLGRIND_REPORT=leakage-callgrind.tsv \
  bash leakage_harness/callgrind_check.sh
gh workflow run "Leakage Profile" --ref main
```

Use `compare` as a local dudect-style timing smoke test. Use `run` under an
external profiler such as `valgrind --tool=callgrind` on Linux, or a platform
equivalent, to compare fixed class workloads without including test harness
branching in the measured operation. `callgrind_check.sh` automates that Linux
workflow by building the native harness, running each sparse/dense class under
callgrind, parsing `summary:` instruction totals, and failing if the percentage
delta exceeds either `LEAKAGE_CALLGRIND_MAX_DELTA_PCT` or the per-workload
limit in `LEAKAGE_CALLGRIND_THRESHOLDS`. Set `LEAKAGE_CALLGRIND_REPORT` to
write a tab-separated report with sparse/dense instruction totals, percentage
delta, selected threshold, and pass/fail result. The manual `Leakage Profile`
workflow runs the same checker against caller-selected workloads and prints a
full TSV report without making normal push CI pay for all private-operation
profiles.

The JWE RSA-OAEP decrypt workload deliberately uses ciphertext `1` and expects
OAEP authentication failure. Because `1^d mod n` is `1` for both sparse and
dense private-exponent classes, the post-modexp OAEP failure path sees the
same encoded message; the class comparison is therefore aimed at private
modexp instruction-count differences rather than data-dependent OAEP parsing.

CI runs two intentionally loose checks in the Linux-only `.#leakage` devShell:

- a tiny timing smoke test (`compare 2 1 1000000`), which only prevents the
  timing harness from rotting;
- a representative callgrind instruction-count smoke test
  (`crypto_bigint-pow_mod`, `p256-sign`) with
  `leakage_harness/callgrind_smoke_thresholds.tsv`, which catches gross
  secret-dependent control-flow or allocation regressions in the profiler
  path without making every CI push run the full slow workload set.

The representative CI callgrind thresholds are currently 1.0%, after the first
Linux CI report showed deltas below 0.003% for both smoke workloads. This is a
useful regression tripwire, not calibrated leakage evidence yet. Tight,
backend-specific thresholds still need repeated Linux measurements before the
checks can be treated as hard constant-time gates.

## Acceptance Criteria

Before upgrading any path from "branchless / fixed-iteration intended" to
"constant-time candidate", require:

- no source-level secret branches in the target path;
- fixed input, output, and limb lengths for the measured API;
- no secret-dependent allocation count in the measured path;
- dudect-style class tests repeatedly below the chosen threshold;
- callgrind-style comparisons with no unexplained secret-dependent instruction
  count deltas;
- separate results for native, wasm, and JS if those targets are advertised for
  the API.

Until those checks exist, the correct description is:

> fixed-limb / fixed-iteration, branchless-intended, not constant-time proven.
