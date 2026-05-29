# Constant-Time Status

This workspace uses four different levels of side-channel language:

- **Fixed-limb** means the arithmetic operates on caller-selected fixed-width
  limb arrays instead of runtime-sized `@bigint` values.
- **Branchless / fixed-iteration intended** means the source avoids
  secret-dependent branches in the target loop and runs a fixed number of
  iterations for a fixed limb width.
- **Measured constant-time candidate** means generated code for a fixed
  workload set passed the repository's repeated timing, dudect-style, and
  callgrind evidence gates on the relevant backends.
- **Constant-clock proven** is stronger: it would require a backend and
  microarchitectural proof beyond the repository's current measurement gates.
  This workspace does not claim that level.

## Current Status

| Area | Status | Remaining risk |
|---|---|---|
| `crypto_bigint` add/sub/mul | Fixed-limb, branchless-intended source loops. | Measured constant-time candidate for the listed workloads in the latest evidence run; allocation and backend lowering are still not a proof. |
| `crypto_bigint` pow | Fixed exponent-width loop. Odd moduli use 32-bit-word Montgomery multiplication. | Measured constant-time candidate for the listed workload; Linux native callgrind stays CI-gated at 1.0%. |
| `crypto_bigint` inv | Fixed-iteration odd-modulus almost-inverse loop. | Final invertible / non-invertible branch is caller-visible; measured candidate only for fixed-size invertible class workloads. |
| RSA sign / JWE RSA-OAEP decrypt | Private modexp routes through `crypto_bigint.Uint::pow_mod`. | Measured constant-time candidate for private modexp workloads; there is still no CRT hardening or blinding. |
| ECDSA final nonce inverse | `p256`, `p384`, `p521`, and `secp256k1` route `k^-1 mod n` through `crypto_bigint.Uint::inv_mod`. | Measured constant-time candidate for the archived direct sparse-vs-dense nonce-inverse workloads except newly added P-521, which still needs repeated calibrated evidence. |
| ECDSA scalar multiplication | P-256, P-384, P-521, and secp256k1 sign-side base-point multiplication use fixed-iteration complete-addition paths. Public verify remains affine `@bigint`. | Measured constant-time candidate for archived sign-side base-point workloads except newly added P-521, which still needs repeated calibrated evidence. |
| P-521 / ES512 signing evidence | P-521 sign-side base-point multiplication and final nonce inverse are fixed-limb / fixed-iteration and registered as `p521-sign` / `p521-nonce-inv`. | Not yet part of archived measured constant-time candidate claims. |
| Ed25519 | 10-limb Edwards field arithmetic with fixed-limb sign-side scalar reduction / mul-add. Public verify scalar parsing remains public `@bigint`. | Measured constant-time candidate for the `ed25519-sign` sparse/dense seed workload. |
| X25519 | 10-limb Montgomery ladder with conditional swaps. | Measured constant-time candidate for the sparse/dense scalar ECDH workload. |
| AES-GCM | AES uses table-based S-boxes. | Not constant-time on shared-cache targets. |
| ChaCha20-Poly1305 | Limb arithmetic, no AES tables. | Backend-level multiply timing and generated code are not audited. |

## Measurement Status

### Latest Archived Evidence

Manual `Leakage Profile` run
[`26587352022`](https://github.com/mizchi/moonbit-crypto/actions/runs/26587352022)
on head `1ff288146603df1dc9b6b1829b3b30a3dc5a81f2` passed
`profile_evidence_gate.sh` on 2026-05-28 UTC. Artifact
[`7271878741`](https://github.com/mizchi/moonbit-crypto/actions/runs/26587352022/artifacts/7271878741)
archives the merged TSVs for the private-operation workload set at that
revision. It predates the `p521-sign` and `p521-nonce-inv` workloads:

- timing evidence: 3 runs for native, JS, wasm-gc, and wasm targets; worst
  row was JS `p384-nonce-inv` with `max_abs_t=12.79`,
  `max_mean_abs_t=7.60`, and zero threshold failures;
- dudect-style evidence: 3 runs for wasm-gc and wasm targets; worst observed
  per-trial row was wasm `crypto_bigint-mul_mod` with `max_abs_t=3.56`,
  while the worst mean row was wasm `crypto_bigint-inv_mod` with
  `max_mean_abs_t=2.27`; both had zero threshold failures;
- callgrind evidence: 3 Linux-native runs for every workload; worst
  instruction-count delta was `jwe-rsa-oaep-decrypt` at `0.036274%`, below
  the current 1.0% evidence threshold.

The workspace now has a Linux-native callgrind instruction-count gate for the
private-operation paths that previously relied on source inspection alone.

1. Dudect-style harnesses now run repeated trial aggregation for:
   - `crypto_bigint.Uint::add_mod`, `sub_mod`, and `mul_mod` with same
     modulus and same public peer operand, split by secret operand class.
   - `crypto_bigint.Uint::pow_mod` with same modulus and base, split by secret
     exponent class.
   - `crypto_bigint.Uint::inv_mod` with same modulus, split by secret input
     class.
   - ECDSA nonce inverses for P-256, P-384, P-521, and secp256k1 order
     moduli, split by sparse-vs-dense nonce class.
   - X25519 ECDH with a fixed basepoint peer key, split by secret scalar
     class.
   - Ed25519 signing with fixed messages, split by sparse-vs-dense seed
     class.
   - RSA sign and JWE RSA-OAEP decrypt with fixed public shape and classed
     private exponent / ciphertext inputs.
2. Callgrind-style instruction-count comparisons exist for the same fixed-size
   classes. These do not prove absence of microarchitectural leakage, but they
   catch obvious secret-dependent control flow and allocation deltas.
3. Signing leakage checks exist for Ed25519, P-256, P-384, P-521, and
   secp256k1 in the Linux-native callgrind gate.
4. CI also runs loose timing smoke checks for JS, wasm-gc, and wasm so backend
   lowering paths keep executing. Treat these as smoke tests only: JIT, GC,
   and BigInt lowering make them unsuitable for strong constant-time claims.

`crypto_bigint/crypto_bigint_bench_test.mbt` contains sparse-vs-dense
`moon bench` inputs for `pow_mod` and `inv_mod`. `p256`, `p384`, and
`secp256k1` also contain sparse-vs-dense private-scalar sign benches. They are
useful for spotting large regressions, but they are not part of the acceptance
criteria.

`leakage_harness` is the measurement entry point used across MoonBit
backends:

```sh
moon run --target native ./leakage_harness -- list
moon run --target native ./leakage_harness -- compare 8 1
moon run --target native ./leakage_harness -- compare-one p256-sign 8 1
moon run --target wasm-gc ./leakage_harness -- dudect-one p256-sign 64 1
bash leakage_harness/dudect_check.sh
LEAKAGE_DUDECT_TARGET=wasm LEAKAGE_DUDECT_WORKLOADS=p256-sign \
  bash leakage_harness/dudect_check.sh
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
bash leakage_harness/profile_summary.sh \
  leakage-timing.tsv leakage-dudect.tsv leakage-callgrind.tsv
bash leakage_harness/profile_evidence_gate.sh leakage-profile-summary.tsv
gh workflow run "Leakage Profile" --ref main
scripts/run_p521_leakage_profile.sh main
```

Use `dudect`, `dudect-one`, or `dudect_check.sh` for in-process
dudect-style smoke tests. Set
`LEAKAGE_DUDECT_TARGET=native|js|wasm-gc|wasm`; the checker default is
`wasm-gc`, and the evidence defaults are `wasm-gc wasm` because native
deployments can prefer OpenSSL / libsodium and JS deployments can prefer
WebCrypto, while wasm / wasm-gc execute this MoonBit-generated code directly.
The native target uses a small C stub for
cycle timing; non-native targets use the MoonBit monotonic clock with balanced
pseudo-random sparse/dense class order. This is still a CI smoke gate unless
run with calibrated measurement counts and archived with the manual evidence
profile. Use `compare`, `compare-one`, or `timing_check.sh` as broader backend
timing smoke tests. `timing_check.sh`
builds the selected harness target
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
shards dudect-style profiles by caller-selected dudect target, shards repeated
timing checks by backend target, shards Linux-native callgrind checks by
workload, then merges the TSV reports before running the evidence gate. Normal
push CI therefore avoids full profiling cost while manual high-sample evidence
runs expose the slow or failing shard directly. The workflow uploads the raw
and aggregated TSV files as GitHub Actions artifacts so a passing high-sample
run can be archived. `scripts/run_p521_leakage_profile.sh` dispatches the
same workflow for the P-521-only workload set (`p521-nonce-inv p521-sign`)
with the evidence gate enabled; use it after the P-521 changes have been
committed and pushed to the selected ref.
`profile_summary.sh` can aggregate one or more timing / dudect / callgrind TSV
reports by target and workload.
`profile_evidence_gate.sh` consumes that summary and fails unless every
selected workload has enough repeated timing evidence for every selected
backend target plus enough wasm-gc / wasm dudect and native callgrind evidence.
Its default evidence inputs require three runs, native / JS / wasm-gc / wasm
timing rows, wasm-gc / wasm dudect rows, zero timing / dudect threshold
failures, and the thresholds in `leakage_harness/timing_evidence_thresholds.tsv`,
`leakage_harness/dudect_evidence_thresholds.tsv`, and
`leakage_harness/callgrind_evidence_thresholds.tsv`.

The JWE RSA-OAEP decrypt workload deliberately uses ciphertext `1` and expects
OAEP authentication failure. Because `1^d mod n` is `1` for both sparse and
dense private-exponent classes, the post-modexp OAEP failure path sees the
same encoded message; the class comparison is therefore aimed at private
modexp instruction-count differences rather than data-dependent OAEP parsing.

CI runs four leakage checks in the Linux-only `.#leakage` devShell:

- wasm-gc / wasm in-process dudect-style smoke tests (`dudect_check.sh` with
  32 randomized measurements, one round, and the loose thresholds from
  `leakage_harness/timing_backend_smoke_thresholds.tsv`), which catch gross
  randomized sparse/dense timing regressions in the generated wasm backends;
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
for a measured candidate claim comes from repeated manual profile summaries
passing `profile_evidence_gate.sh`, not from the ordinary CI smoke thresholds.

## Acceptance Criteria

Before upgrading any new path from "branchless / fixed-iteration intended" to
"measured constant-time candidate", require:

- no source-level secret branches in the target path;
- fixed input, output, and limb lengths for the measured API;
- no secret-dependent allocation count in the measured path;
- dudect-style class tests repeatedly below the chosen threshold;
- callgrind-style comparisons with no unexplained secret-dependent instruction
  count deltas;
- a passing `profile_evidence_gate.sh` summary with repeated native, JS,
  wasm-gc, and wasm timing rows plus repeated wasm-gc / wasm dudect and native
  callgrind rows for every advertised private-operation workload.

For the archived pre-P-521 workload set, those checks exist in run
`26587352022`. The correct description for those covered paths is:

> fixed-limb / fixed-iteration, branchless-intended, measured constant-time
> candidate for the archived workload set, not constant-clock proven.
