# BetterTLS name-constraints vectors

Sampled subset of the Netflix [BetterTLS](https://github.com/Netflix/bettertls)
`nameconstraints` suite, obtained via the
[C2SP/x509-limbo](https://github.com/C2SP/x509-limbo) corpus, which republishes
BetterTLS under its `bettertls::` namespace (`limbo.json`, schema `version: 1`).

These cases put name constraints on **intermediate** CAs (root → ICA(NC) →
… → leaf), which is exactly the path that `@pkix_verify.verify_chain` enforces
— and the location of the disjoint-`permittedSubtrees` intersection bypass
fixed in PR #2. The `pathbuilding` sub-suite (which needs path discovery the
verifier does not perform) is excluded.

## Sampling and soundness

Only cases whose requested peer name equals one of the leaf's SAN entries are
kept, so identity always matches and the verdict is determined by the name
constraints / chain alone (the verifier does not do hostname matching). The
large suite is sampled deterministically by `scripts/gen_x509_limbo.py`,
preserving the reject/accept split (caps: 150 reject, 55 accept).

`reject` cases that involve IP name constraints (which this verifier does not
implement) are still correct here because the verifier fails closed on them;
the matching `accept` cases are tolerated as skips by the harness.

## Consumed by

`pkix_verify/limbo_json_js_test.mbt` (JS target). The hard assertion is the
false-positive guard: no `reject` case may verify.

## Regenerating

See `testdata/x509-limbo/README.md`.

## SHA-256

```text
85c810cb5f26aae3e78703596b4beff43a36a7639c71754e99c2dfd22ab7bcc1  nameconstraints.json
```
