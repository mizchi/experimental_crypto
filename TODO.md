# Known Issues / TODO

Status of `mizchi/moonbit-crypto` after the "fix all known issues" sweep
(commits `7d98af4`, `d3f8d7b`).

## ✓ Closed in this sweep

- **PGP `creation_time` hardcoded** → `sign_armor(..., creation_time?=…)`
  parameter (default 1700000000U for reproducible tests).
- **PEM (lax) unbounded line length** → `pem_max_line_length = 8 KiB`
  enforced inside `decode_all`.
- **pkix_verify validity time-string format** → `normalize_time` now
  raises on anything other than exact UTCTime (13 chars + Z) or
  GeneralizedTime (15 chars + Z); digits-only check on the body.
- **pkix_verify intermediate `signature_algorithm` vs `tbs.signature`**
  → cross-check added to `verify_certificate`; mismatch raises
  `UnsupportedSignatureAlgorithm`.
- **asn1 `from_arcs` validation** → new `from_arcs_checked` raises
  `InvalidEncoding` for callers that take OIDs from untrusted input.
  `from_arcs` (abort-on-bad-arg) unchanged for back-compat.
- **secp256k1 module** → new `mizchi/secp256k1` with ECDSA sign + verify
  (RFC 6979 + low-s normalisation by default per BIP-62). Same attack
  test set as `@p256`.
- **RSA-PSS sign + verify** → `@rsa.{sign,verify}_pss` with MGF1 +
  EMSA-PSS encoding. `@jwt` exposes `Ps256/384/512` (deterministic
  sLen=0 internally; full RFC 7518 interop needs caller-supplied salt
  via `@rsa.sign_pss` directly).
- **PBES2 encrypted PKCS#8** → `@pkcs8.{decrypt,decrypt_pem}` handling
  PBKDF2-HMAC-SHA256 + AES-{128,256}-CBC + PKCS#7 unpadding. Inverse
  AES cipher added to `@aead`.

## Still open

### Security gaps (no exploit, documented in source)

- **ECDSA / RSA sign side-channel**: `scalar_mult` (P-256/P-384/secp256k1)
  and `@bigint.pow` are variable-time on the secret. Doc-commented in
  each `PrivateKey::sign`. Fix needs constant-time scalar mult + modexp,
  which in turn needs `crypto_bigint` rewritten as a real limb-based
  implementation. Tier 1 effort, ~1 week per curve.
- **pkix_verify DN linkage is byte-compare**: doesn't implement LDAPv3
  string-prep (case-insensitive for PrintableString). Refuses some
  valid chains rather than accepting wrong ones, so safe but
  restrictive.
- **JWT `kid` not sanitised**: returned verbatim; caller responsibility.
- **PKCS#8 v2 publicKey consistency**: a v2 record with a `[1]` field
  whose contents don't match the algorithm OID's public-key shape is
  accepted (caller's problem on use).
- **CMS encrypted-blob OID not validated** (`pkcs8.parse_encrypted_der`):
  by design — decryption is a separate layer. Caller matches on OID
  before invoking any decryptor.

### Missing algorithms / protocols

#### Tier 1 remaining

- **PGP v6 packets (RFC 9580)**: new key + signature layouts. GnuPG ≥ 2.4
  defaults to v6.
- **gpgsm real cert X.509 chain test**: requires generating an S/MIME
  cert chain and signing a commit with `gpg --gpgsm --sign`. Exercises
  `@cms.verify_with_chain` end-to-end.

#### Tier 2 (≈1 week each)

- **TLS 1.3 client**: handshake + key schedule (HKDF-Expand-Label) +
  record layer. All cryptographic primitives are already here.
- **JWE (RFC 7516)**: RSA-OAEP / AES-KW / ECDH-ES key wrap +
  AES-GCM / ChaCha20-Poly1305 content encryption.
- **COSE / CBOR (RFC 8949 + 9052)**: WebAuthn / FIDO2 attestation, CWT.
- **BIP-39 + BIP-32 HD wallets** (now that secp256k1 is in): mnemonic
  phrases + hierarchical derivation paths. Crypto-wallet baseline.
- **OCSP / CRL revocation check**: parses + verifies, no network. Adds
  a missing piece to chain verification (today we accept revoked certs).
- **PBES2 RNG-backed randomised PSS for JWT**: surface a salt-supply
  hook in `@jwt.Key::Ps256/384/512` so callers with a real RNG can
  produce RFC 7518-compliant JWTs.

#### Tier 3 (longer, less common)

- **Post-quantum (ML-KEM, ML-DSA)**: FIPS 203 / 204. Cutting-edge.
- **Ed448 / X448** (RFC 8032 / 7748): higher security level than Ed25519.
- **PKCS#12 (PFX)**: Windows / macOS keychain interop.
- **AES-GCM-SIV / AES-SIV**: nonce-misuse-resistant AEADs.
- **scrypt-based PBES2**: less common openssl encrypted PEM mode.
- **PBES2 HMAC-SHA1 / SHA-384 / SHA-512 PRF support** in `@pkcs8`
  (currently rejects with `UnsupportedKdf`).
- **AES-192-CBC** in `@aead.aes_cbc` (needs a 3rd branch in
  `aes_key_schedule`).

### Test coverage / robustness

- **PGP gpg-binary interoperability**: current `pgp_test.mbt` only
  verifies sign+verify roundtrips with our own implementation
  (tautology for sign). A CI step that pipes our armor into
  `gpg --verify` would catch sign-side drift.
- **Cross-format fuzz**: pkcs8/asn1/pem fuzz harnesses are in place but
  don't exercise the integration boundaries.
- **Constant-time verification**: we use `@hash.ct_eq` for MAC tags and
  RSA EM comparison, but the surrounding logic (e.g. PGP signature
  packet parsing) does early-exit. Confirm no secret-dependent timing
  leaks via an external profiler.

### Performance / footprint

- **`crypto_bigint`** is currently a thin wrapper around `@bigint`.
  Real limb-based implementation would unlock CT mod-exp and ~2-4× perf
  on ECDSA/RSA sign. Tracked under the Tier-1 ECDSA timing fix above.
- **`asn1` encoder double-pass for nested structures**: streaming
  encoder with length-back-patching would halve the cost.
- **AES-GCM GHASH bit-by-bit fallback**: `gcm.mbt` uses a 4-bit Shoup
  table. PCLMULQDQ-style carry-less mult would be ~10×; not portable
  to wasm-gc without intrinsics.
- **`ed25519` 10-limb field arithmetic**: same speedup the `x25519`
  module got (14× ECDH). Currently uses `@bigint` Edwards-curve
  arithmetic.

### Documentation

- README dedicated "git commit signing" section with the three
  end-to-end flows (SSH / PGP / X.509-CMS).
- README listing the new `mizchi/secp256k1` module alongside `p256`/`p384`.
