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
| `crypto_bigint` add/sub/mul | Fixed-limb, branchless-intended source loops. | No direct per-primitive external measurement yet; allocation and backend lowering are not fully audited. |
| `crypto_bigint` pow | Fixed exponent-width loop. Odd moduli use 32-bit-word Montgomery multiplication. | Linux native callgrind sparse/dense workload is CI-gated at 1.0%; no dudect-style statistical gate yet. |
| `crypto_bigint` inv | Fixed-iteration odd-modulus almost-inverse loop. | Final invertible / non-invertible branch is caller-visible; Linux native callgrind sparse/dense workload is CI-gated at 1.0%. |
| RSA sign / JWE RSA-OAEP decrypt | Private modexp routes through `crypto_bigint.Uint::pow_mod`. | Linux native callgrind sparse/dense workloads are CI-gated at 1.0%; no CRT hardening, blinding, or dudect-style statistical gate yet. |
| ECDSA final nonce inverse | `p256`, `p384`, and `secp256k1` route `k^-1 mod n` through `crypto_bigint.Uint::inv_mod`. | Covered indirectly by Linux native callgrind sign workloads; no direct inverse-only dudect-style gate yet. |
| ECDSA scalar multiplication | P-256, P-384, and secp256k1 sign-side base-point multiplication use fixed-iteration complete-addition paths. Public verify remains affine `@bigint`. | Linux native callgrind sign workloads are CI-gated at 1.0%; wasm / JS and dudect-style timing remain smoke-only. |
| Ed25519 | Still `@bigint`-backed Edwards arithmetic. | Limb rewrite pending. |
| X25519 | 10-limb Montgomery ladder with conditional swaps. | Backend-level constant-time behavior is not proven. |
| AES-GCM | AES uses table-based S-boxes. | Not constant-time on shared-cache targets. |
| ChaCha20-Poly1305 | Limb arithmetic, no AES tables. | Backend-level multiply timing and generated code are not audited. |

## Measurement Status

The workspace now has a Linux-native callgrind instruction-count gate for the
private-operation paths that previously relied on source inspection alone.

1. Native dudect-style harnesses still need stronger statistical treatment for:
   - `crypto_bigint.Uint::pow_mod` with same modulus and base, split by secret
     exponent class.
   - `crypto_bigint.Uint::inv_mod` with same modulus, split by secret input
     class.
   - RSA sign and JWE RSA-OAEP decrypt with fixed public shape and classed
     private exponent / ciphertext inputs.
2. Callgrind-style instruction-count comparisons exist for the same fixed-size
   classes. These do not prove absence of microarchitectural leakage, but they
   catch obvious secret-dependent control flow and allocation deltas.
3. ECDSA signing leakage checks exist for P-256, P-384, and secp256k1 in the
   Linux-native callgrind gate.
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
moon run --target native ./leakage_harness -- compare-one p256-sign 8 1
bash leakage_harness/timing_check.sh
LEAKAGE_TIMING_THRESHOLDS=leakage_harness/timing_smoke_thresholds.tsv \
  LEAKAGE_TIMING_REPORT=leakage-timing.tsv \
  bash leakage_harness/timing_check.sh
LEAKAGE_TIMING_TARGET=js LEAKAGE_TIMING_WORKLOADS=crypto_bigint-pow_mod \
  bash leakage_harness/timing_check.sh
moon run --target native ./leakage_harness -- run p256-sign sparse 100
moon run --target native ./leakage_harness -- run p256-sign dense 100
bash leakage_harness/callgrind_check.sh
nix develop --impure .#leakage --command bash leakage_harness/callgrind_check.sh
LEAKAGE_CALLGRIND_THRESHOLDS=leakage_harness/callgrind_smoke_thresholds.tsv \
  LEAKAGE_CALLGRIND_REPORT=leakage-callgrind.tsv \
  bash leakage_harness/callgrind_check.sh
gh workflow run "Leakage Profile" --ref main
```

Use `compare`, `compare-one`, or `timing_check.sh` as local dudect-style timing
smoke tests. `timing_check.sh` builds the selected harness target
(`LEAKAGE_TIMING_TARGET=native|js|wasm-gc|wasm`), runs caller-selected
workloads, applies either `LEAKAGE_TIMING_MAX_ABS_T` or per-workload thresholds
from `LEAKAGE_TIMING_THRESHOLDS`, and can write a TSV report via
`LEAKAGE_TIMING_REPORT`. Non-native targets use `moon run` and should still be
treated as smoke-only because JIT / runtime effects dominate. Use `run` under
an external profiler such as
`valgrind --tool=callgrind` on Linux, or a platform equivalent, to compare
fixed class workloads without including test harness branching in the measured
operation. `callgrind_check.sh` automates that Linux workflow by building the
native harness, running each sparse/dense class under callgrind, parsing
`summary:` instruction totals, and failing if the percentage delta exceeds
either `LEAKAGE_CALLGRIND_MAX_DELTA_PCT` or the per-workload limit in
`LEAKAGE_CALLGRIND_THRESHOLDS`. Set `LEAKAGE_CALLGRIND_REPORT` to write a
tab-separated report with sparse/dense instruction totals, percentage delta,
selected threshold, and pass/fail result. The manual `Leakage Profile` workflow
runs timing checks against caller-selected backend targets, then runs the
Linux-native callgrind checker, and prints TSV reports without making normal
push CI pay for full profiling.

The JWE RSA-OAEP decrypt workload deliberately uses ciphertext `1` and expects
OAEP authentication failure. Because `1^d mod n` is `1` for both sparse and
dense private-exponent classes, the post-modexp OAEP failure path sees the
same encoded message; the class comparison is therefore aimed at private
modexp instruction-count differences rather than data-dependent OAEP parsing.

CI runs two checks in the Linux-only `.#leakage` devShell:

- a loose timing smoke test (`timing_check.sh` with eight samples and
  `leakage_harness/timing_smoke_thresholds.tsv`), which catches only very
  large sparse/dense timing regressions and keeps report plumbing from
  rotting;
- a callgrind instruction-count gate for every current private-operation
  workload in `leakage_harness/callgrind_smoke_thresholds.tsv`, which catches
  gross secret-dependent control-flow or allocation regressions in the profiler
  path.

The CI callgrind thresholds are currently 1.0%. The first full Linux profile
run after introducing the manual workflow produced:

| Workload | Sparse Ir | Dense Ir | Delta |
|---|---:|---:|---:|
| `crypto_bigint-pow_mod` | 10,885,060 | 10,884,681 | 0.003482% |
| `crypto_bigint-inv_mod` | 13,865,760 | 13,865,318 | 0.003188% |
| `rsa-pkcs1v15-sign` | 1,483,320,050 | 1,483,860,724 | 0.036437% |
| `jwe-rsa-oaep-decrypt` | 1,483,968,124 | 1,484,508,860 | 0.036425% |
| `p256-sign` | 163,948,756 | 163,949,841 | 0.000662% |
| `p384-sign` | 350,467,440 | 350,467,283 | 0.000045% |
| `secp256k1-sign` | 150,180,452 | 150,182,138 | 0.001123% |

The 1.0% gate is intentionally wider than the first profile to avoid CI noise
while still failing closed on large instruction-count regressions. Repeated
Linux profile runs can tighten the per-workload thresholds further.

The timing smoke thresholds are deliberately loose (`abs_t <= 20.0`) because
they run inside ordinary GitHub-hosted runners. They are a regression tripwire,
not calibrated dudect evidence.

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
