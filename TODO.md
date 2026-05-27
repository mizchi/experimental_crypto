# Known Issues / TODO

Active backlog for `mizchi/moonbit-crypto`. Completed items were moved to
`DONE.md`.

## Security Implementation Priority

1. [ ] **Constant-time secret-key operations**: remove secret-dependent timing
   from `crypto_bigint`, RSA private modexp, and ECDSA scalar multiplication.
   - [x] Move `crypto_bigint` modular add/sub/mul/pow and Montgomery reduction
     off the BigInt fallback onto fixed-limb code.
   - [x] Replace `crypto_bigint.inv_mod`'s BigInt-backed extended-GCD fallback
     with a limb-based odd-modulus binary-GCD path.
   - [x] Replace variable-time `crypto_bigint.inv_mod` with a fixed-iteration
     algorithm before using it on secret inverses.
   - [x] Wire RSA PKCS#1 v1.5 / PSS sign-side private modexp to fixed-limb
     modular exponentiation.
   - [x] Wire JWE RSA-OAEP private decrypt modexp to fixed-limb modular
     exponentiation.
   - [x] Route ECDSA nonce inverses away from `@bigint.pow` and through
     `crypto_bigint.inv_mod`.
   - [x] Route P-256 sign-side base-point scalar multiplication through the
     fixed-iteration complete-addition field path. This is not external
     constant-time evidence yet.
   - [ ] Replace ECDSA scalar multiplication with fixed-limb constant-time
     implementations for the remaining curves and verify them externally.
   - [ ] Add external leakage checks (`dudect` / callgrind-style harness) for
     RSA/JWE private operations and ECDSA sign paths. Measurement scope and
     terminology are in `docs/CONSTANT_TIME.md`.
2. [ ] **PGP sign-side interop**: verify generated signatures with external
   `gpg`, `sq`, or `rsop`.
   - [x] Add external sign-output verification for v4 signatures.
   - [ ] Add v6 sign-output verification once a v6-capable reference tool is
     available in CI.
3. [ ] **JWT remaining algorithm / parser coverage**.
   - [ ] Add `ES512` only after a P-521 implementation exists.
4. [ ] **SSH allowed_signers feature gaps**.
   - [ ] Add explicit SSH certificate support before accepting
     `cert-authority`.
   - [ ] Add a time-aware allowed_signers API before accepting
     `valid-after` / `valid-before`.
5. [ ] **Cross-format fuzz breadth**.
   - [ ] Add CMS -> PKIX -> PKIX_VERIFY fuzz.
   - [ ] Add OCSP / CRL -> PKIX_VERIFY fuzz.

## Authentication False-Positive Policy

False negatives are acceptable for unsupported / ambiguous inputs. False
positives are not. A feature can be deferred only if the verifier or parser
fails closed before returning authenticated / verified / trusted.

### Cannot Defer Unless It Already Fails Closed

- **PKIX / CMS / COSE signature acceptance**: critical extensions,
  AlgorithmIdentifier mismatches, signed-attribute digest binding, certificate
  path constraints, name constraints, KU/EKU, and unknown critical structures
  must reject.
- **OCSP / CRL revocation decisions used for trust**: delta CRL, indirect CRL,
  CRL distribution-point matching, delegated responder authorization, and
  request-bound OCSP nonce semantics must either be implemented or rejected by
  the high-level trust API.
- **JWT / OIDC / JARM / DPoP / JWKS trust boundaries**: `alg`, `kid`, `typ`,
  issuer, audience, nonce/state, token binding (`cnf.jkt`, `ath`,
  `at_hash`/`c_hash`), duplicate JWKS keys, and embedded remote key hints must
  remain strict.
- **SSH allowed_signers trust policy**: `cert-authority`, `valid-after`, and
  `valid-before` must stay fail-closed until certificate and time-aware
  verification APIs exist.
- **git signed-object canonical bytes**: raw object headers, tag objects,
  multi-line `gpgsig` continuation, duplicate signatures, and body-only
  `gpgsig` text must remain unambiguous.
- **PGP verify-side packet semantics**: signature type, hash algorithm,
  public-key algorithm, v6 salt, MPI/raw signature encoding, and trailing packet
  data must be strict.
- **Password / key container parsers that gate trust**: PHC, PBES2, PKCS#8,
  ASN.1, PEM, and JWK parsers must reject duplicate fields, non-canonical
  base64 / DER, impossible lengths, and unknown critical choices before using
  decoded key material.

### Can Defer If Fail-Closed Today

- **New algorithm support**: `ES512` / P-521, Ed448 / X448, ML-KEM / ML-DSA,
  AES-GCM-SIV / AES-SIV, `age`, EIP-712 / EIP-191, TLS 1.3, PKCS#12, and
  BIP-32 CKDpub can wait while unsupported inputs raise errors.
- **Interop-only sign output checks**: external `gpg` / `sq` / `rsop`
  validation of signatures we produce mostly causes false negatives with other
  tools rather than false positives in our verifiers.
- **Coverage expansion after strict behavior exists**: more fuzzing for
  CMS -> PKIX -> PKIX_VERIFY and OCSP / CRL -> PKIX_VERIFY is valuable, but the
  immediate false-positive control is fail-closed behavior.
- **Leakage measurement harnesses**: `dudect` / callgrind-style checks are not
  direct authentication false-positive controls, but remain high priority for
  production signing keys.

## Algorithm Gaps

### Tier 1

- [ ] **TLS 1.3 client**: handshake + key schedule (HKDF-Expand-Label) +
  record layer. All cryptographic primitives are already here.

### Tier 2 / 3

- [ ] **BIP-32 CKDpub for non-hardened indices**: needs a public point-add API
  on `@secp256k1.PublicKey`.
- [ ] **PGP v6 real-gpg fixture**: blocked on GnuPG >= 2.4.9 emitting v4 by
  default. Cross-test once rpgpie / rsop / a v6-capable gpg becomes available.
- [ ] **Post-quantum ML-KEM / ML-DSA** (FIPS 203 / 204).
- [ ] **Ed448 / X448** (RFC 8032 / 7748).
- [ ] **PKCS#12 (PFX)**.
- [ ] **AES-GCM-SIV / AES-SIV** nonce-misuse-resistant AEADs.
- [ ] **OCSP / CRL extension feature support**: archive cutoff, delta-CRLs,
  CRL distribution-point matching, indirect CRLs, and OCSP HTTP client
  execution. High-level CRL trust APIs currently reject unsupported scoped /
  delta / indirect semantics fail-closed, and OCSP exposes request DER plus
  POST metadata without performing network I/O.
- [ ] **`age`** file encryption format.
- [ ] **EIP-712 / EIP-191** structured Ethereum signing helpers.

## Security Gaps

- [ ] **ECDSA / private-operation side-channel**: ECDSA `scalar_mult` remains
  variable-time on secrets for P-384 and secp256k1. RSA sign and JWE RSA-OAEP
  private modexp now use `crypto_bigint`'s fixed-limb path, ECDSA final nonce
  inverses no longer use `@bigint.pow`, and P-256 sign-side base-point scalar
  multiplication uses fixed-iteration complete addition. The remaining ECDSA
  risk is unmeasured leakage plus the affine, branch-dependent scalar
  multiplication still used by P-384 and secp256k1.
- [ ] **PSS RNG-backed sign in JWT**: PS256/384/512 currently uses
  deterministic PSS (`sLen = 0`) because the workspace has no vetted RNG at the
  JWT layer. RFC 7518 mandates `sLen = hLen`; callers needing full interop call
  `@rsa.sign_pss` directly with a freshly sampled salt.

## Formal Methods

- [ ] Remove the `partial_prover` shim in `proofs/why3.conf` once Why3 1.7.2
  recognises Z3 4.16 / CVC5 1.3 natively.
- [ ] Add proof targets for `pbkdf2` block count, `argon2` memory alignment,
  `bip32` `is_hardened`, `crypto_bigint` `limb_count`, and `totp`
  time-bucket monotonicity.
- [ ] Revisit `ct_select` bitmask proofs once `moon prove` lowers `&`, `|`,
  and `lnot` to a bitvector theory.

## Test Coverage / Robustness

- [ ] **JWT remaining coverage holes**: unsupported / fixture-heavy ES512
  branch after P-521 exists.
- [ ] **Cross-format fuzz breadth**: PEM -> ASN.1 -> PKCS#8 / PKIX integration
  fuzzing exists; extend to CMS / OCSP / CRL and JOSE containers.
- [ ] **Constant-time verification** via external profiler (`dudect` /
  `valgrind --tool=callgrind`) for `crypto_bigint`, RSA/JWE private
  operations, and ECDSA signing once scalar multiplication is fixed. Scope and
  acceptance criteria are documented in `docs/CONSTANT_TIME.md`.

## Performance / Footprint

- [ ] **`crypto_bigint` remaining work**: wire remaining ECDSA secret
  operations to the limb implementation and add external leakage measurement.
- [ ] **ECDSA field rewrite**: move p256/p384/secp256k1 scalar multiplication
  off affine BigInt point formulas; previous attempt to route every field
  inverse through fixed-iteration `crypto_bigint.inv_mod` made full JS tests
  impractically slow.
  - [x] Add P-256 10-limb field I/O, canonical reduction, add/sub/neg, and
    interim fixed-width mul/square/inversion helpers with BigInt oracle tests.
  - [x] Add P-256 projective point conversion, double/add, and branchy scalar
    multiplication baseline against the existing affine oracle.
  - [x] Add P-256 field / projective point conditional-select helpers.
  - [x] Add a P-256 fixed-256-iteration scalar multiplication skeleton. It is
    not wired into signing because point addition still has exceptional-case
    branches.
  - [x] Add complete / exceptional-case-free P-256 formulas, then wire private
    scalar multiplication away from affine `@bigint`.
  - [x] Add P-384 crypto_bigint-backed complete-addition formulas and oracle
    tests. Keep scalar/sign wiring disconnected for now because the fixed
    scalar loop made JS tests too slow without a dedicated reducer.
  - [ ] Add a performant P-384 fixed scalar path, then wire private scalar
    multiplication away from affine `@bigint`.
  - [ ] Port the fixed-iteration complete-addition private scalar path to
    secp256k1.
- [ ] **`asn1` encoder** streaming with length-back-patching.
- [ ] **AES-GCM GHASH** carry-less-multiplication path.
- [ ] **`ed25519`** 10-limb field arithmetic, matching the speedup already
  obtained in `x25519`.

## Documentation

- [ ] Update top-level `README.md` module map + perf table to reflect the
  current 35-module workspace.
- [ ] Add README "git commit signing" walkthrough for SSH / PGP / X.509-CMS.
- [ ] Migrate per-module quickstart blocks into generated
  `pkg.generated.mbti` docs once moon's doc tooling catches up.

## CI / Infra

- [ ] Investigate native test runner noise:
  `warning: unhandled Platform key FamilyDisplayName`.
- [ ] Resolve the FlakeHub auth warning emitted by
  `DeterminateSystems/nix-installer-action`.
- [ ] Cache `~/.moon/registry` between CI runs so `moon update` does not
  re-fetch `moonbitlang/x` each time.
