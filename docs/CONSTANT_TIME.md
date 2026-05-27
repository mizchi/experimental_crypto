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
| ECDSA scalar multiplication | P-256 and secp256k1 sign-side base-point multiplication use fixed-iteration complete-addition paths. P-384 sign still uses affine `@bigint` point arithmetic. | P-384 has secret-dependent branches and field inversions; all ECDSA sign paths still need external leakage measurement. |
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
3. Add ECDSA signing leakage checks for P-256 and secp256k1, and add P-384
   checks after its scalar multiplication moves off affine `@bigint`.
4. Treat JavaScript timing checks as smoke tests only. JIT, GC, and BigInt
   lowering make JS unsuitable for strong constant-time claims.

`crypto_bigint/crypto_bigint_bench_test.mbt` contains sparse-vs-dense
`moon bench` inputs for `pow_mod` and `inv_mod`. They are useful for spotting
large regressions, but they are not part of the acceptance criteria.

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
