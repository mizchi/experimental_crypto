# Known Issues / TODO

Active backlog for `mizchi/moonbit-crypto`. Completed items were moved to
`DONE.md`.

## Security Implementation Priority

1. [ ] **PGP sign-side interop**: verify generated signatures with external
   `gpg`, `sq`, or `rsop`.
   - [x] Add external sign-output verification for v4 signatures.
   - [ ] Add v6 sign-output verification once a v6-capable reference tool is
     available in CI.
2. [ ] **JWT remaining algorithm / parser coverage**.
   - [ ] Add `ES512` only after a P-521 implementation exists.
3. [ ] **SSH allowed_signers feature gaps**.
   - [ ] Add explicit SSH certificate support before accepting
     `cert-authority`.
   - [x] Add a time-aware allowed_signers API before accepting
     `valid-after` / `valid-before`.
4. [x] **Cross-format fuzz breadth**.
   - [x] Add CMS -> PKIX -> PKIX_VERIFY fuzz.
   - [x] Add OCSP / CRL -> PKIX_VERIFY fuzz.

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
- **SSH allowed_signers trust policy**: `cert-authority` must stay fail-closed
  until certificate verification exists. `valid-after` / `valid-before` must
  be enforced only by explicit time-aware verification APIs; plain verification
  must keep time-scoped entries fail-closed.
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

## Formal Methods

- [ ] Remove the `partial_prover` shim in `proofs/why3.conf` once Why3 1.7.2
  recognises Z3 4.16 / CVC5 1.3 natively.
- [ ] Revisit `ct_select` bitmask proofs once `moon prove` lowers `&`, `|`,
  and `lnot` to a bitvector theory.

## Test Coverage / Robustness

- [ ] **JWT remaining coverage holes**: unsupported / fixture-heavy ES512
  branch after P-521 exists.

## Performance / Footprint

- [ ] **Leakage threshold tightening**: after additional Linux profile history,
  tighten the conservative 1.0% callgrind thresholds and evidence timing /
  dudect thresholds for fixed-limb private operations. Current measured status
  and archived evidence are documented in `docs/CONSTANT_TIME.md`.
- [ ] **`asn1` encoder** streaming with length-back-patching.
- [ ] **AES-GCM GHASH** carry-less-multiplication path.

## Documentation

- [ ] Migrate per-module quickstart blocks into generated
  `pkg.generated.mbti` docs once moon's doc tooling catches up.
