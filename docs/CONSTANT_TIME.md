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
| `crypto_bigint` pow | Fixed exponent-width loop. Odd moduli use 32-bit-word Montgomery multiplication. | Linux native callgrind sparse/dense workload is CI-gated at 1.0%; native timing now has a repeated dudect-style smoke gate, but not calibrated proof. |
| `crypto_bigint` inv | Fixed-iteration odd-modulus almost-inverse loop. | Final invertible / non-invertible branch is caller-visible; Linux native callgrind sparse/dense workload is CI-gated at 1.0%. |
| RSA sign / JWE RSA-OAEP decrypt | Private modexp routes through `crypto_bigint.Uint::pow_mod`. | Linux native callgrind sparse/dense workloads are CI-gated at 1.0%; native timing now has a repeated dudect-style smoke gate, but there is no CRT hardening or blinding. |
| ECDSA final nonce inverse | `p256`, `p384`, and `secp256k1` route `k^-1 mod n` through `crypto_bigint.Uint::inv_mod`. | Covered by direct sparse-vs-dense nonce-inverse timing workloads plus Linux native callgrind smoke gates. |
| ECDSA scalar multiplication | P-256, P-384, and secp256k1 sign-side base-point multiplication use fixed-iteration complete-addition paths. Public verify remains affine `@bigint`. | Linux native callgrind sign workloads are CI-gated at 1.0%; native timing has a repeated dudect-style smoke gate, while JS / wasm-gc / wasm are CI smoke-only. |
| Ed25519 | Still `@bigint`-backed Edwards arithmetic. | Limb rewrite pending. |
| X25519 | 10-limb Montgomery ladder with conditional swaps. | Backend-level constant-time behavior is not proven. |
| AES-GCM | AES uses table-based S-boxes. | Not constant-time on shared-cache targets. |
| ChaCha20-Poly1305 | Limb arithmetic, no AES tables. | Backend-level multiply timing and generated code are not audited. |

## Measurement Status

The workspace now has a Linux-native callgrind instruction-count gate for the
private-operation paths that previously relied on source inspection alone.

1. Native dudect-style harnesses now run repeated trial aggregation for:
   - `crypto_bigint.Uint::pow_mod` with same modulus and base, split by secret
     exponent class.
   - `crypto_bigint.Uint::inv_mod` with same modulus, split by secret input
     class.
   - ECDSA nonce inverses for P-256, P-384, and secp256k1 order moduli,
     split by sparse-vs-dense nonce class.
   - RSA sign and JWE RSA-OAEP decrypt with fixed public shape and classed
     private exponent / ciphertext inputs.
2. Callgrind-style instruction-count comparisons exist for the same fixed-size
   classes. These do not prove absence of microarchitectural leakage, but they
   catch obvious secret-dependent control flow and allocation deltas.
3. ECDSA signing leakage checks exist for P-256, P-384, and secp256k1 in the
   Linux-native callgrind gate.
4. CI also runs loose timing smoke checks for JS, wasm-gc, and wasm so backend
   lowering paths keep executing. Treat these as smoke tests only: JIT, GC,
   and BigInt lowering make them unsuitable for strong constant-time claims.

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
bash leakage_harness/profile_summary.sh leakage-timing.tsv leakage-callgrind.tsv
bash leakage_harness/profile_evidence_gate.sh leakage-profile-summary.tsv
gh workflow run "Leakage Profile" --ref main
```

Use `compare`, `compare-one`, or `timing_check.sh` as local dudect-style timing
smoke tests. `timing_check.sh` builds the selected harness target
(`LEAKAGE_TIMING_TARGET=native|js|wasm-gc|wasm`), runs caller-selected
workloads, and can repeat the Welch t-test using `LEAKAGE_TIMING_TRIALS`.
Threshold files use `workload max_abs_t max_mean_abs_t max_failures`; older
two-column files still mean `workload max_abs_t`. The checker gates both the
per-trial `abs_t` and the mean `abs_t`, tracks failed trial count, and can
write a summary TSV via `LEAKAGE_TIMING_REPORT`. Non-native targets use
`moon run` and should still be treated as smoke-only because JIT / runtime
effects dominate. Use `run` under an external profiler such as
`valgrind --tool=callgrind` on Linux, or a platform equivalent, to compare
fixed class workloads without including test harness branching in the measured
operation. `callgrind_check.sh` automates that Linux workflow by building the
native harness, running each sparse/dense class under callgrind, parsing
`summary:` instruction totals, and failing if the percentage delta exceeds
either `LEAKAGE_CALLGRIND_MAX_DELTA_PCT` or the per-workload limit in
`LEAKAGE_CALLGRIND_THRESHOLDS`. Set `LEAKAGE_CALLGRIND_REPORT` to write a
tab-separated report with sparse/dense instruction totals, percentage delta,
selected threshold, and pass/fail result. The manual `Leakage Profile` workflow
runs repeated timing checks against caller-selected backend targets, then runs
the Linux-native callgrind checker for each repetition, and prints TSV reports
without making normal push CI pay for full profiling. `profile_summary.sh` can
aggregate one or more timing / callgrind TSV reports by target and workload.
`profile_evidence_gate.sh` consumes that summary and fails unless every
selected workload has enough repeated timing evidence for every selected
backend target plus enough native callgrind evidence. Its default evidence
inputs require three runs, native / JS / wasm-gc / wasm timing rows, zero
timing threshold failures, and the thresholds in
`leakage_harness/timing_evidence_thresholds.tsv` and
`leakage_harness/callgrind_evidence_thresholds.tsv`.

The JWE RSA-OAEP decrypt workload deliberately uses ciphertext `1` and expects
OAEP authentication failure. Because `1^d mod n` is `1` for both sparse and
dense private-exponent classes, the post-modexp OAEP failure path sees the
same encoded message; the class comparison is therefore aimed at private
modexp instruction-count differences rather than data-dependent OAEP parsing.

CI runs three leakage checks in the Linux-only `.#leakage` devShell:

- a repeated timing smoke test (`timing_check.sh` with eight samples, three
  independent trials, `max_abs_t <= 20.0`, `mean_abs_t <= 10.0`, and zero
  tolerated threshold failures from
  `leakage_harness/timing_smoke_thresholds.tsv`), which catches sustained
  sparse/dense timing regressions and keeps report plumbing from rotting;
- a backend-breadth timing smoke test for JS, wasm-gc, and wasm with two
  samples, one trial, and loose `max_abs_t <= 100.0` /
  `mean_abs_t <= 100.0` thresholds from
  `leakage_harness/timing_backend_smoke_thresholds.tsv`, which is a
  regression tripwire for non-native lowering paths;
- a callgrind instruction-count gate for every current private-operation
  workload in `leakage_harness/callgrind_smoke_thresholds.tsv`, which catches
  gross secret-dependent control-flow or allocation regressions in the profiler
  path.

The CI callgrind thresholds are currently 1.0%. The first full Linux profile
run after introducing the manual workflow, before adding the direct
nonce-inverse workloads, produced:

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

The timing smoke thresholds are deliberately loose because they run inside
ordinary GitHub-hosted runners. They are stronger than a single timing sample
because CI now requires three independent trials with `mean_abs_t <= 10.0` and
no per-trial threshold failures, but they are still a regression tripwire, not
calibrated dudect evidence.

The backend smoke thresholds are looser still. They exist to keep JS, wasm-gc,
and wasm code-generation paths under sparse-vs-dense workload observation, not
to justify a constant-time claim for those runtimes. Backend-breadth evidence
for a future claim must come from the repeated manual profile summary passing
`profile_evidence_gate.sh`, not from the ordinary CI smoke thresholds.

## Acceptance Criteria

Before upgrading any path from "branchless / fixed-iteration intended" to
"constant-time candidate", require:

- no source-level secret branches in the target path;
- fixed input, output, and limb lengths for the measured API;
- no secret-dependent allocation count in the measured path;
- dudect-style class tests repeatedly below the chosen threshold;
- callgrind-style comparisons with no unexplained secret-dependent instruction
  count deltas;
- a passing `profile_evidence_gate.sh` summary with repeated native, JS,
  wasm-gc, and wasm timing rows plus repeated native callgrind rows for every
  advertised private-operation workload.

Until those checks exist, the correct description is:

> fixed-limb / fixed-iteration, branchless-intended, not constant-time proven.
