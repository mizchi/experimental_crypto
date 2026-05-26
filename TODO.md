# Known Issues / TODO

Status of `mizchi/moonbit-crypto` after the T1+T2 sweep
(commits `d3f8d7b`, `f66b7a1`).

## ✓ Closed

| Item | Module | Commit |
|---|---|---|
| secp256k1 verify + sign (BIP-62 low-s default) | `secp256k1` | d3f8d7b |
| RSA-PSS (PS256/384/512) | `rsa` + `jwt` | d3f8d7b |
| PBES2 encrypted PKCS#8 + AES-CBC | `pkcs8` + `aead` | d3f8d7b |
| PGP `creation_time` parameterised | `pgp` | 7d98af4 |
| PEM per-line cap (8 KiB) | `pem` | 7d98af4 |
| pkix_verify strict validity-time format | `pkix_verify` | 7d98af4 |
| pkix_verify outer/inner signature_algorithm cross-check | `pkix_verify` | 7d98af4 |
| asn1 `from_arcs_checked` Result variant | `asn1` | 7d98af4 |
| JWE (RFC 7516: dir / RSA-OAEP-256 / A256KW + A128/256GCM) | `jwe` | f66b7a1 |
| CBOR (RFC 8949 minimum viable) | `cbor` | f66b7a1 |
| COSE_Sign1 verify + COSE_Key + WebAuthn attestation | `cose` | f66b7a1 |
| BIP-39 (English wordlist + PBKDF2-HMAC-SHA512) | `bip39` | f66b7a1 |
| BIP-32 HD wallets (CKDpriv + derive_path, hardened + non-hardened) | `bip32` | f66b7a1 |
| RIPEMD-160 + HASH160 in @hash (BIP-32 fingerprint) | `hash` | f66b7a1 |
| SHA-1 in @hash (legacy OCSP CertID) | `hash` | f66b7a1 |
| secp256k1 `PublicKey::to_compressed` (BIP-32) | `secp256k1` | f66b7a1 |
| OCSP response parse + verify (RFC 6960) | `ocsp` | f66b7a1 |
| CRL parse + verify (RFC 5280 §5) | `crl` | f66b7a1 |
| PGP v6 packets (RFC 9580) verify + sign-roundtrip | `pgp` | f66b7a1 |
| gpgsm-style real cert chain test for `@cms.verify_with_chain` | `cms` | f66b7a1 |

## Still open

### ASN.1 / PEM security review follow-up

- [x] Reject non-canonical ASN.1 high-tag-number forms, including low tag
  numbers encoded in high-tag form and leading-zero base-128 tag encodings.
- [x] Reject DER universal tag form mismatches such as constructed INTEGER and
  primitive SEQUENCE / SET.
- [x] Decode multi-byte OID first subidentifiers correctly and reject
  non-minimal OID base-128 encodings.
- [x] Reject BIT STRING encodings whose unused tail bits are not zero.
- [x] Validate PEM labels on decode and encode so control characters,
  lowercase labels, or newline-bearing labels cannot create ambiguous armor.
- [x] Enforce schema-aware DER SET ordering in PKIX RDNs and PKCS#8
  attributes.
- [x] Tighten PKIX validity UTCTime / GeneralizedTime syntax at parse and
  encode boundaries.
- [x] Reject non-positive PKIX certificate serial numbers and duplicate
  optional TBSCertificate fields.
- [x] Validate context-specific / IMPLICIT BIT STRING tail padding at PKIX and
  PKCS#8 parser boundaries.
- [x] Reject duplicate PKCS#8 optional `attributes` and `publicKey` fields.
- [x] Enforce generic DER SET / SET OF canonical ordering in the ASN.1 decoder
  and sort SET items at encode time.
- [x] Tighten generic ASN.1 string/time types beyond ASCII:
  PrintableString alphabet, UTCTime / GeneralizedTime syntax, and canonical
  timezone forms.
- [x] Add integration fuzzing across PEM -> ASN.1 -> PKCS#8 / PKIX parser
  boundaries.

### HPKE / JWK / TOTP / BLAKE3 security review follow-up

- [x] Check HPKE sequence exhaustion before AEAD Seal/Open, so a context at
  the message limit cannot perform one extra encryption/decryption attempt.
- [x] Validate public-all HPKE AEAD context shape (`key`, `base_nonce`) before
  nonce computation / AEAD calls.
- [x] Reject invalid HPKE LabeledExpand output lengths before truncating the
  two-byte `L` prefix.
- [x] Reject invalid JWK RSA public parameters (`n <= 1`, even `n`,
  `e < 3`, even `e`) and non-positive private exponents.
- [x] Reject EC / Ed25519 private JWKs whose `d` does not derive the supplied
  public `x` / `y`.
- [x] Treat JWK `oct` as private-only: `parse_public` rejects it and
  `serialise_public` no longer emits the symmetric secret `k`.
- [x] Fail closed on invalid TOTP parameters: digits outside 6..8, non-positive
  step, `now < T0`, and excessive verification skew.
- [x] Encode BLAKE3 derive-key context strings as UTF-8 and pin a non-ASCII
  reference vector.

### SSH security review follow-up

- [x] Stop describing `ssh` as an OpenSSH verifier; document it as a
  conservative SSHSIG-style subset.
- [x] Fail closed on `allowed_signers` entries with `cert-authority`,
  `valid-after`, or `valid-before` until SSH certificates and time-aware
  verification are implemented.
- [x] Parse comma-separated `allowed_signers` options without dropping
  `namespaces="..."` constraints.
- [x] Reject empty SSHSIG namespaces at sign/verify boundaries.
- [x] Reject non-minimal SSH `mpint` encodings in parsed SSH keys/signatures.
- [x] Add structured fuzz / mutation tests for `allowed_signers` options,
  SSHSIG envelope fields, inner signature algorithms, and SSH `mpint`
  canonicality.
- [ ] Add a strict SSHSIG armor decoder for trust decisions. Current decoder is
  intentionally lax about surrounding whitespace.
- [ ] Add explicit SSH certificate support before accepting `cert-authority`.
- [ ] Add a time-aware allowed_signers API before accepting
  `valid-after` / `valid-before`.

### Security gaps (no exploit, documented in source)

- **ECDSA / RSA sign side-channel**: `scalar_mult` and `@bigint.pow` are
  variable-time on the secret. Doc-commented in each `PrivateKey::sign`
  (p256/p384/secp256k1/rsa). Fix needs constant-time scalar mult +
  modexp, which in turn needs `crypto_bigint` rewritten as a real
  limb-based implementation.
- **JWT `kid` not sanitised**: returned verbatim; caller responsibility.
- **PKCS#8 v2 publicKey consistency**: a v2 record with a `[1]` field
  whose contents don't match the algorithm OID's public-key shape is
  accepted (caller's problem on use).
- **PSS RNG-backed sign in JWT**: PS256/384/512 currently uses
  deterministic PSS (sLen = 0) since the workspace has no vetted RNG
  at the JWT layer. RFC 7518 mandates sLen = hLen; callers needing
  full interop call `@rsa.sign_pss` directly with a freshly-sampled
  salt. Documented.

### Remaining algorithm gaps

#### Tier 1

- **TLS 1.3 client** (deferred from this sweep): handshake + key
  schedule (HKDF-Expand-Label) + record layer. All cryptographic
  primitives are already here.

#### Tier 2 / 3

- **BIP-32 CKDpub for non-hardened indices**: needs a public point-add
  API on `@secp256k1.PublicKey`. Hardened path + neuter already work.
- **PGP v6 real-gpg fixture**: blocked on GnuPG ≥ 2.4.9 emitting v4 by
  default. Cross-test once rpgpie / rsop / a v6-capable gpg becomes
  available.
- **PGP v6 caller-supplied salt** in `sign_armor` (currently empty;
  RFC requires ≥16 bytes for production).
- **PBES2 HMAC-SHA1 / SHA-384 / SHA-512 PRF support** in `@pkcs8`
  (currently rejects with `UnsupportedKdf`).
- **AES-192-CBC** in `@aead.aes_cbc` (needs a 3rd branch in
  `aes_key_schedule`).
- **scrypt-based PBES2**: less common openssl encrypted PEM mode.
- **Post-quantum (ML-KEM, ML-DSA)**: FIPS 203 / 204.
- **Ed448 / X448** (RFC 8032 / 7748).
- **PKCS#12 (PFX)**.
- **AES-GCM-SIV / AES-SIV** nonce-misuse-resistant AEADs.
- **OCSP / CRL extensions**: nonce, archive cutoff, delta-CRLs,
  CRL distribution-point matching, indirect CRLs,
  `id-pkix-ocsp-nocheck` on delegated responders, OCSP request
  construction, HTTP transport.

### Test coverage / robustness

- **PGP gpg-binary interop**: `pgp_test.mbt` sign side is currently
  tautological (sign+verify with our own code). A CI step piping our
  armor into `gpg --verify` would catch sign-side drift.
- **Cross-format fuzz breadth**: PEM -> ASN.1 -> PKCS#8 / PKIX integration
  fuzzing exists; extend similar integration checks to CMS / OCSP / CRL and
  JOSE containers.
- **Constant-time verification** via external profiler.

### Performance / footprint

- **`crypto_bigint`** real limb-based implementation (unlocks CT modexp,
  ~2-4× sign perf).
- **`asn1` encoder** streaming with length-back-patching (cuts a tree
  walk).
- **AES-GCM GHASH** carry-less-multiplication path (not portable to
  wasm-gc without intrinsics).
- **`ed25519`** 10-limb field arithmetic (the speedup `x25519` already
  got — 14× ECDH).

### Documentation

- README "git commit signing" section with the three end-to-end flows
  (SSH / PGP / X.509-CMS).
- README listing all new modules (secp256k1, jwe, cbor, cose, bip39,
  bip32, ocsp, crl).
