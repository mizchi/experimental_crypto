# Known Issues / TODO

Tracking known gaps in `mizchi/moonbit-crypto`. None of these are
exploitable security bugs in the deployed sign+verify path — that surface
was closed in commits `20b1b94`, `ee0654b`, `861d87a` after three rounds
of independent code review. The items below are either residual
hardening work, missing algorithms, or test coverage gaps.

## Security gaps with no current exploit

These are documented in source and have either explicit doc comments
warning callers (cryptographic) or a structural mitigation (parser).

- **ECDSA / RSA sign side-channel** (`p256/p256.mbt`, `p384/p384.mbt`,
  `rsa/rsa.mbt`): `scalar_mult` and `@bigint.pow` are variable-time on
  the secret. RFC 6979 only addresses nonce bias / reuse, not timing.
  A network or co-tenant attacker who can trigger many sign operations
  may recover the private key. **Mitigation**: each `PrivateKey::sign`
  carries a doc comment marking it as a trusted-host primitive.
  **Fix**: implement a constant-time Montgomery-ladder scalar mult and
  a constant-time modular exponentiation (windowed, fixed-trace). Tier-1
  effort: ~1 week per curve, requires rewriting `crypto_bigint` from a
  `@bigint` wrapper into a real limb-based implementation.

- **PGP `creation_time` hardcoded** (`pgp/pgp.mbt:225`): every signature
  emitted by `sign_armor` carries a fixed creation-time subpacket
  (2023-11-14). Not a security issue, but a side-channel for "this
  signature was produced by mizchi/pgp" and would fail any verifier that
  enforces a "signed within the last N hours" policy. **Fix**:
  parameterise `creation_time` as an optional argument.

- **pkix_verify validity time-string format** (`pkix_verify/pkix_verify.mbt:657`):
  `normalize_time` handles UTCTime (length 13) and "already YYYY..." (≥15).
  Inputs with fractional seconds, time-zone offsets, or non-`Z` suffixes
  produce wrong lexicographic ordering. **Fix**: tighten format check
  to require exactly 13/15 chars ending in `Z`; raise on anything else.

- **pkix_verify DN linkage is byte-compare** (`pkix_verify/pkix_verify.mbt:728`):
  RFC 5280 §7.1 allows LDAPv3 string-prep (case-insensitive for
  PrintableString attributes). Two valid certs with `CN=example.com` vs
  `CN=Example.com` will fail linkage. **Refuses valid chains**, not a
  security bug. **Fix**: implement string-prep for PrintableString.

- **JWT `kid` not sanitised** (`jwt/jwt.mbt:440`): returned to caller
  verbatim. A caller using `kid` as a file-system path or URL is exposed
  to traversal. **Caller responsibility**; document in the README.

- **pkix_verify intermediate `signature_algorithm` vs `tbs.signature`**
  (`pkix_verify/pkix_verify.mbt`): RFC 5280 §4.1.1.2 / §4.1.2.3 require
  the outer `signature_algorithm` and the inner `tbs.signature` to
  encode the same OID. Our verifier doesn't cross-check (the `pkix`
  parser may already enforce this — needs verification). **Fix**: add
  an explicit equality check in `verify_certificate`.

- **PEM (lax) unbounded line length** (`pem/pem.mbt`): `decode` /
  `decode_all` only enforce `pem_max_input_size = 16 MiB` on the whole
  input, not per-line. A 16 MiB single-line payload is parsed in one
  allocation. **Fix**: add an optional per-line cap (e.g. 8 KiB).

- **CMS encrypted-blob OID not validated** (`pkcs8/pkcs8.mbt`):
  `parse_encrypted_der` doesn't validate the algorithm OID; this is by
  design (decryption is a separate layer). **Caller responsibility**:
  match on `info.algorithm.algorithm` before invoking any decryptor.

- **PKCS#8 v2 publicKey consistency** (`pkcs8/pkcs8.mbt:250`): when
  `version=1` (v2) carries a `[1]` publicKey field, we don't validate
  that the public key matches the algorithm OID. Stored verbatim;
  caller's problem on use. **Fix**: cross-check when both are present.

- **CMS `[0] subjectKeyIdentifier` SignerIdentifier**
  (`cms/cms.mbt:268`): currently raises `UnsupportedSid`. The
  `IssuerAndSerialNumber` branch covers openssl/gpgsm output, which is
  what we care about for git X.509 signing. **Fix**: add SKI matching
  against cert SubjectKeyIdentifier extensions.

## Missing algorithms / protocols

Concrete work, no security risk in the current API.

### Tier 1 (1–3 days each, reuses existing templates)

- **secp256k1 verify + sign**: copy of `@p256` with different curve
  constants + low-s normalisation + recovery id. Unlocks Bitcoin TX
  signing, Ethereum `personal_sign` / EIP-712.
- **RSA-PSS sign + verify (PS256/384/512)**: needs MGF1 + EMSA-PSS
  encoding. Modern TLS 1.3 certs use PSS exclusively for RSA.
- **PGP v6 packets (RFC 9580)**: new key + signature layouts. Used by
  GnuPG ≥ 2.4 by default. Sub-1 day for verify-only.
- **PBES2 encrypted PEM**: PKCS#5 KDF (PBKDF2 + AES-CBC) for
  `openssl genpkey -aes256` output. Reuses `@pbkdf2` + `@aead`.
- **gpgsm real cert X.509 chain test**: requires generating an S/MIME
  cert chain and signing a commit with `gpg --gpgsm --sign`. Exercises
  `@cms.verify_with_chain` end-to-end.

### Tier 2 (≈1 week each)

- **TLS 1.3 client**: handshake + key schedule (HKDF-Expand-Label) +
  record layer. All cryptographic primitives are already here.
- **JWE (RFC 7516)**: RSA-OAEP / AES-KW / ECDH-ES key wrap +
  AES-GCM / ChaCha20-Poly1305 content encryption.
- **COSE / CBOR (RFC 8949 + 9052)**: WebAuthn / FIDO2 attestation, CWT.
- **BIP-39 + BIP-32 HD wallets** (after secp256k1): mnemonic phrases +
  hierarchical derivation paths. Crypto-wallet baseline.
- **OCSP / CRL revocation check**: parses + verifies, no network. Adds
  a missing piece to chain verification (today we accept revoked certs).

### Tier 3 (longer, less common)

- **Post-quantum (ML-KEM, ML-DSA)**: FIPS 203 / 204. Cutting-edge.
- **Ed448 / X448** (RFC 8032 / 7748): higher security level than Ed25519.
- **PKCS#12 (PFX)**: Windows / macOS keychain interop.
- **AES-GCM-SIV / AES-SIV**: nonce-misuse-resistant AEADs.

## Test coverage / robustness improvements

- **`asn1.ObjectIdentifier::from_arcs` validation** currently uses
  `abort()` because the constructor signature can't raise without a
  breaking change to `derive(Eq)`. Catch-side regression tests aren't
  possible because aborts terminate the runtime. **Fix**: change the
  signature to `raise Asn1Error` (breaks ABI) or expose
  `from_arcs_checked` returning `Result`.

- **pkix_verify pathLenConstraint fuzz**: deterministic tests for
  pathLen=0..3 across 4-deep chains. We have one positive + one negative
  test; a property-based fuzz would catch off-by-one regressions if the
  chain-walk indexing is ever refactored.

- **PGP gpg-binary interoperability**: current `pgp_test.mbt` only
  verifies sign+verify roundtrips with our own implementation
  (tautology). The verify-side test against a real `gpg --detach-sign`
  signature is in place (`pgp: verify_armor against real gpg signature`)
  but the sign-side has no `gpg --verify` consumer. **Fix**: CI step
  that pipes our armor into `gpg --verify`.

- **Cross-format fuzz**: pkcs8/asn1/pem fuzz harnesses are in place but
  don't exercise the integration boundaries (e.g. random PKCS#8 →
  RsaPrivateKey extraction). **Fix**: cross-module fuzz harness.

- **Constant-time verification**: we use `@hash.ct_eq` for MAC tags and
  RSA EM comparison, but the surrounding logic (e.g. PGP signature
  packet parsing) does early-exit. Confirm no secret-dependent timing
  leaks via an external profiler.

## Performance / footprint

- **`crypto_bigint`** is currently a thin wrapper around `@bigint`.
  Real limb-based implementation would unlock CT mod-exp and ~2-4× perf
  on ECDSA/RSA sign. Tracked under the Tier-1 ECDSA timing fix above.

- **`asn1` encoder double-pass for nested structures**: the current
  single-pass code computes `value_encoded_size` first then writes —
  for deeply nested types this walks the tree twice. A streaming
  encoder with length-back-patching would halve the cost.

- **AES-GCM GHASH bit-by-bit fallback**: `gcm.mbt` uses a 4-bit Shoup
  table. PCLMULQDQ-style carry-less mult would be ~10×; not portable
  to wasm-gc without intrinsics.

- **`ed25519` 10-limb field arithmetic**: same speedup the `x25519`
  module got (14× ECDH). Currently uses `@bigint` Edwards-curve
  arithmetic.

## Documentation

- README listing of `mizchi/git_object` + `mizchi/cms` + `mizchi/pgp` +
  `mizchi/ssh` is implicit. Add a dedicated "git commit signing" section
  with the three end-to-end flows (SSH / PGP / X.509-CMS).
- Side-channel caveat doc for every `PrivateKey::sign` is in source but
  not surfaced in README.
