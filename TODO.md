# Known Issues / TODO

Active backlog for `mizchi/moonbit-crypto`. Completed items were moved to
`DONE.md`.

## Security Implementation Priority

1. [x] **PGP sign-side interop**: verify generated signatures with external
   `gpg`, `sq`, or `rsop`.
   - [x] Add external sign-output verification for v4 signatures.
   - [x] Run v4 Ed25519 sign-output verification with `gpg --verify` in CI.
   - [x] Run v6 Ed25519 sign-output verification with Sequoia `sq verify` in
     CI.
2. [ ] **JWT remaining algorithm / parser coverage**.
   - [x] Add `ES512` after adding P-521 / secp521r1 support.
   - [x] Reject malformed optional string claims in OIDC ID Token, RFC 9068,
     and DPoP profile verifiers.
   - [x] Reject malformed optional string claims in RFC 7523 client assertions,
     logout tokens, UserInfo, JARM, SIOP, and CIBA profile verifiers.
   - [x] Reject malformed `typ` JOSE headers instead of treating them as
     absent in generic verifiers.
   - [x] Reject malformed registered JWT claims (`iss`, `sub`, `jti`, `aud`)
     in generic `verify`, even when no issuer / audience option is supplied.
3. [x] **Cross-format fuzz breadth**.
   - [x] Add CMS -> PKIX -> PKIX_VERIFY fuzz.
   - [x] Add OCSP / CRL -> PKIX_VERIFY fuzz.

## Authentication False-Positive Policy

False negatives are acceptable for unsupported / ambiguous inputs. False
positives are not. A feature can be deferred only if the verifier or parser
fails closed before returning authenticated / verified / trusted.

### Cannot Defer Unless It Already Fails Closed

Use this checklist as the authentication false-positive gate. Checked items
mean the current high-level parser / verifier either implements the rule or
rejects unsupported inputs before returning trusted output.

- [x] **PKIX / CMS / COSE signature acceptance**
  - [x] Reject unknown / recognised-but-unenforced critical certificate
    extensions before chain trust.
  - [x] Reject AlgorithmIdentifier and digest/signature algorithm mismatches.
  - [x] Bind CMS signed attributes to `contentType` and `messageDigest`.
  - [x] Enforce certificate path constraints, name constraints, KU/EKU, and
    pathLen before returning a trusted chain.
  - [x] Reject ambiguous duplicate signer certificates, duplicate extension
    OIDs, and duplicate protected COSE labels.
- [x] **OCSP / CRL revocation decisions used for trust**
  - [x] Reject delta CRLs, indirect CRLs, scoped distribution-point CRLs, and
    unsupported CRL / entry extensions until their semantics are implemented.
  - [x] Reject OCSP responses with unsupported response / single extensions.
  - [x] Reject delegated OCSP responders unless signer authority, EKU,
    `id-pkix-ocsp-nocheck`, and issuer binding all validate.
  - [x] Keep nonce-bearing OCSP responses fail-closed unless checked through
    the request-bound nonce API.
  - [x] Require freshness bounds (`nextUpdate`) before returning revocation
    status.
- [x] **JWT / OIDC / JARM / DPoP / JWKS trust boundaries**
  - [x] Keep `alg`, `kid`, `typ`, issuer, audience, nonce/state, and token
    binding (`cnf.jkt`, `ath`, `at_hash` / `c_hash`) strict.
  - [x] Reject duplicate JWKS `kid` values and malformed JWKS metadata strings
    at parse time.
  - [x] Reject embedded remote key hints (`jku`, `x5u`) by never fetching or
    trusting them in high-level verifiers.
  - [x] Reject malformed optional string arrays and discovery endpoint strings
    instead of silently treating present bad fields as absent.
  - [x] Reject malformed JAR `client_id` claims when present, rather than
    bypassing embedded client binding.
- [x] **SSH allowed_signers trust policy**
  - [x] Accept `cert-authority` only through explicit OpenSSH user-certificate
    validation and time-aware verification APIs.
  - [x] Enforce `valid-after` / `valid-before` only via explicit time-aware
    verification APIs.
  - [x] Keep plain verification fail-closed for time-scoped and certificate
    authority entries.
- [x] **git signed-object canonical bytes**
  - [x] Keep raw object headers, tag objects, multi-line `gpgsig`
    continuation, duplicate signatures, and body-only `gpgsig` text
    unambiguous before signature verification.
- [x] **PGP verify-side packet / armor semantics**
  - [x] Reject unsupported signature type, hash algorithm, public-key
    algorithm, v6 salt shape, and non-minimal MPI / raw signature encodings.
  - [x] Reject detached signature armor with extra packets or trailing packet
    data.
  - [x] Reject non-empty trailing data after ASCII armor END lines before using
    verified packet data.
  - [x] Reject ambiguous public-key armor envelopes before returning primary
    key material.
- [x] **Password / key container parsers that gate trust**
  - [x] Reject PHC / PBES2 duplicate fields and non-canonical base64.
  - [x] Reject ASN.1 / DER non-canonical encodings, impossible lengths, and
    unknown critical choices before decoded key material is used.
  - [x] Use strict PEM decoding for PKCS#8 private-key containers.
  - [x] Reject JWK duplicate JSON fields, malformed metadata, non-canonical
    base64url, and non-minimal RSA integer encodings.

### Can Defer If Fail-Closed Today

- **New algorithm support**: Ed448 / X448, ML-KEM / ML-DSA, AES-GCM-SIV /
  AES-SIV, `age`, EIP-712 / EIP-191, TLS 1.3, and PKCS#12 can wait while
  unsupported inputs raise errors.
- **Interop-only sign output checks**: external `gpg` / `sq` / `rsop`
  validation of signatures we produce mostly causes false negatives with other
  tools rather than false positives in our verifiers.
- **Coverage expansion after strict behavior exists**: additional generated /
  reference vectors are valuable, but the immediate false-positive control is
  fail-closed behavior.
- **Leakage measurement harnesses**: `dudect` / callgrind-style checks are not
  direct authentication false-positive controls, but remain high priority for
  production signing keys.

## Algorithm Gaps

### Tier 1

- [ ] **TLS 1.3 client**: handshake + key schedule (HKDF-Expand-Label) +
  record layer. All cryptographic primitives are already here.

### Tier 2 / 3

- [ ] **PGP v6 GnuPG-specific fixture**: blocked on GnuPG 2.4.9 emitting v4
  by default. v6 sign-side interop is covered by Sequoia `sq`; cross-test with
  GnuPG / rsop once a compatible tool is available.
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

## Formal Methods

- [ ] Remove the `partial_prover` shim in `proofs/why3.conf` once Why3 1.7.2
  recognises Z3 4.16 / CVC5 1.3 natively.
- [ ] Revisit `ct_select` bitmask proofs once `moon prove` lowers `&`, `|`,
  and `lnot` to a bitvector theory.

## Test Coverage / Robustness

- [ ] **JWT remaining coverage holes**: continue adding reference fixtures for
  profile-specific JWT/OIDC/FAPI branches as they are touched.
- [x] **x509-limbo / BetterTLS path-validation differential corpus**: replay
  the C2SP/x509-limbo + Netflix BetterTLS name-constraint suites against
  `pkix_verify.verify_chain` (`pkix_verify/limbo_json_js_test.mbt`,
  `scripts/gen_x509_limbo.py`, fixtures under `testdata/{x509-limbo,bettertls}`).
  Hard assertion: no `reject` case verifies (false-positive guard).
- [ ] **Trust-anchor-level constraint enforcement**: `verify_chain` treats the
  trust anchor as a bare public key and does NOT inspect the anchor's own
  validity window, basicConstraints, critical extensions, or `nameConstraints`.
  A caller that pins a name-constrained or expired root has those properties
  silently dropped (surfaced by the excluded x509-limbo `*root*` / anchor
  `nc::` cases). Intermediate-level constraints ARE enforced. Decide whether to
  accept a full anchor `Certificate` (and enforce its constraints/validity) or
  document this as a hard API contract.

## Performance / Footprint

- [ ] **Leakage threshold tightening**: after additional Linux profile history,
  tighten the conservative 1.0% callgrind thresholds and evidence timing /
  dudect thresholds for fixed-limb private operations. Current measured status
  and archived evidence are documented in `docs/CONSTANT_TIME.md`.
- [ ] **P-521 archived leakage evidence**: run the manual `Leakage Profile`
  workflow for the P-521-inclusive workload set and update
  `docs/CONSTANT_TIME.md` once repeated timing / dudect / callgrind evidence
  passes on Linux CI artifacts. Use `scripts/run_p521_leakage_profile.sh`
  after committing and pushing the candidate ref.
- [ ] **AES-GCM GHASH hardware CLMUL**: current portable GHASH uses a 4-bit
  Shoup table; replace it with a backend carry-less-multiplication / SIMD path
  once MoonBit exposes a suitable intrinsic.

## Documentation

- [ ] Migrate per-module quickstart blocks into generated
  `pkg.generated.mbti` docs once moon's doc tooling catches up.
