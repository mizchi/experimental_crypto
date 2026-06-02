# experimental_crypto

> **Status: experimental — not for production.** This workspace exists to
> fill gaps in the MoonBit ecosystem so other people writing MoonBit code
> have something to read and reuse. **None of the modules have been
> independently audited.** Constant-time discipline, side-channel
> resistance, and on-wire format edge cases are documented but not
> certified.
>
> If you use any of this code in a real system, you are responsible for
> reviewing the source first and confirming it meets your security
> requirements. The author disclaims all liability for use. Prefer a
> vetted library (`RustCrypto`, `dalek`, `BoringSSL`, etc.) wherever one
> exists for your protocol.

Pure MoonBit building blocks for crypto, PKI, JOSE, and signing formats.
Everything lives in a single MoonBit module, `mizchi/experimental_crypto`, with
each library/protocol shipped as a sub-package you import by path (for example
`mizchi/experimental_crypto/asn1`, aliased `@asn1`). It currently has 40
library/protocol sub-packages plus the `proofs` and `leakage_harness` sidecars.
The implementations stay on top of `moonbitlang/core`, a small `moonbitlang/x`
dependency for platform hooks, and the other sub-packages in this module.

The constant-time properties of the field arithmetic are not yet up to
the bar of `dalek` or `RustCrypto`; the file headers call out exactly
where the gaps are.

## Packages and RFC coverage

Every sub-package, the RFC / specification it implements, and a one-line role.
Import each by path — e.g. `mizchi/experimental_crypto/asn1` (alias `@asn1`).
For API-level detail see [docs/MODULES.md](docs/MODULES.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Layer 1 — encoding & foundations**

| Package | RFC / Spec | Role |
|---|---|---|
| `asn1` | X.690 (DER) / X.680 | Strict canonical DER encoder + decoder (MAX_DEPTH=32). |
| `cbor` | RFC 8949 | CBOR major types 0–7 + tags; consumed by COSE / WebAuthn. |
| `crypto_bigint` | — (RustCrypto crypto-bigint shape) | Fixed-limb unsigned ints, modular arithmetic, Montgomery pow. |
| `getrandom` | — (platform CSPRNG) | `crypto.getRandomValues` / `arc4random_buf` / `getrandom(2)` / `BCryptGenRandom`. |
| `keygen` | FIPS 186-5, RFC 8017 | `generateKey` for P-256 / P-384 / Ed25519 / X25519 + RSA (Miller–Rabin prime search) key pairs (CSPRNG-backed; native/js). |

**Layer 2 — primitives (hashes, AEAD, KDFs, container parsers)**

| Package | RFC / Spec | Role |
|---|---|---|
| `hash` | FIPS 180-4, RFC 2104, ISO 10118-3, BLAKE2/3 | SHA-1/256/384/512, RIPEMD-160, HMAC-SHA-2, BLAKE2b/3, `ct_eq`. |
| `sha3` | FIPS 202 | Keccak-f[1600]: SHA3-256/512 + SHAKE128/256 (used by ML-KEM). |
| `mlkem` | FIPS 203 | ML-KEM-768 post-quantum KEM (keygen / encaps / decaps; KAT-verified). |
| `pqhybrid` | draft-kwiatkowski-tls-ecdhe-mlkem (0x11ec) | X25519MLKEM768 hybrid KEX (ML-KEM-768 ‖ X25519) for TLS 1.3 — browser default. |
| `aead` | RFC 8439, NIST SP 800-38D / 38A | ChaCha20- / XChaCha20-Poly1305, AES-128/256-GCM, AES-CBC, AES-CTR. |
| `aeskw` | RFC 3394 | AES Key Wrap / Unwrap (128/192/256-bit KEK); used by `jwe` A256KW. |
| `pkix` | RFC 5280 | X.509 v3 parse + byte-stable DER round-trip. |
| `pkcs8` | RFC 5208 / 5958, RFC 8018 | PrivateKeyInfo + EncryptedPrivateKeyInfo (PBES2). |
| `pem` | RFC 7468 | PEM encode / decode with strict label + size caps. |
| `hkdf` | RFC 5869 | HKDF-Extract + Expand on HMAC-SHA-256. |
| `pbkdf2` | RFC 8018 | PBKDF2-HMAC-SHA-256. |
| `scrypt` | RFC 7914 | scrypt + PHC string encode / verify. |
| `argon2` | RFC 9106 | Argon2d / i / id + PHC string encode / verify. |

**Layer 3 — signature & ECDH primitives**

| Package | RFC / Spec | Role |
|---|---|---|
| `ed25519` | RFC 8032 | Ed25519 sign + verify (+ `verify_strict`). |
| `x25519` | RFC 7748 | X25519 ECDH (10-limb Montgomery ladder). |
| `p256` | FIPS 186-5, SEC 1, RFC 5903 | ECDSA-SHA-256 sign (RFC 6979) + verify, ECDH. |
| `p384` | FIPS 186-5, RFC 5903 | ECDSA-SHA-384 sign + verify, ECDH. |
| `p521` | FIPS 186-5 | ECDSA-SHA-512 (ES512) sign + verify. |
| `secp256k1` | SEC 2 §2.4.1 | ECDSA + RFC 6979 + BIP-62 low-s (Bitcoin / Ethereum). |
| `rsa` | RFC 8017 | RSA PKCS#1 v1.5 + RSA-PSS sign + verify, RSA-OAEP (SHA-1/256/384/512 + label) encrypt / decrypt. |

**Layer 4 — composers & verifiers**

| Package | RFC / Spec | Role |
|---|---|---|
| `pkix_verify` | RFC 5280 §6 | X.509 chain validation (Ed25519 / RSA / ECDSA-SHA-2). |
| `naclbox` | libsodium `crypto_box` (XChaCha20) | Curve25519 + XChaCha20-Poly1305 box. |
| `hpke` | RFC 9180 | Mode_Base DHKEM(X25519) / HKDF-SHA256 / ChaCha20Poly1305. |
| `ech` | draft-ietf-tls-esni (0xfe0d) | Encrypted ClientHello: ECHConfigList parse + HPKE seal/open of the inner CH. |
| `webpush` | RFC 8291 / 8188 | Web Push `aes128gcm` message decrypt (P-256 ECDH + HKDF). |
| `bip39` | BIP-39 | Mnemonic ↔ entropy + PBKDF2-HMAC-SHA-512 seed. |
| `bip32` | BIP-32 | HD key derivation on secp256k1. |
| `cose` | RFC 9052 | COSE_Sign1 verify + COSE_Key parser. |

**Layer 5 — application formats & protocols**

| Package | RFC / Spec | Role |
|---|---|---|
| `jwt` | RFC 7515 / 7519 / 7518 | JWS / JWT sign + verify (HS / RS / PS / ES / EdDSA). |
| `jwe` | RFC 7516 / 7518 | JWE compact (dir / RSA-OAEP-256 / A256KW + A128/256GCM). |
| `jwk` | RFC 7517 / 7518 / 7638 / 8037 | JWK parse / serialise / thumbprint. |
| `totp` | RFC 4226 / 6238 | HOTP / TOTP + provisioning URI. |
| `pgp` | RFC 9580 (+ RFC 4880) | OpenPGP v4 / v6 detached signature verify + sign. |
| `ssh` | SSHSIG-style subset | SSHSIG armor sign + verify + OpenSSH user certs. |
| `cms` | RFC 5652 | CMS SignedData detached verify. |
| `git_object` | git object format | Commit / tag signature extraction. |
| `ocsp` | RFC 6960 | OCSP response parse + verify. |
| `ct` | RFC 6962 | Certificate Transparency SCT list parse + signature verify (x509 / precert entry). |
| `crl` | RFC 5280 §5 | CRL parse + verify + `is_revoked`. |
| `webauthn` | W3C WebAuthn L2 / FIDO CTAP2 | Assertion + attestation (packed / fido-u2f / none) verification. |
| `age_format` | C2SP age v1 | age file decrypt + deterministic encrypt for X25519 recipients. |
| `noise` | Noise Protocol Framework | NN / NK / XX / IK handshake state machine (25519 + ChaChaPoly + SHA256). |
| `tls13` | RFC 8446 (vectors: RFC 8448) | TLS 1.3 client 1-RTT handshake building blocks (live glue WIP). |
| `tls12` | RFC 5246/5288/7627/8422, RFC 6066/6960 | TLS 1.2 PRF + key schedule + AES-GCM records + ECDHE handshake + verified server auth (chain + hostname + SKE + OCSP stapling). |
| `quic` | RFC 9001 | QUIC v1 Initial key derivation + AES-128-GCM packet protection + AES header-protection mask (vectors: RFC 9001 App. A). |

**Sidecars**

| Package | RFC / Spec | Role |
|---|---|---|
| `proofs` | — | SMT proof leaves (`moon prove` + Why3 + Z3). |
| `leakage_harness` | — | Native sparse-vs-dense leakage measurement. |

`moon test` from the module root runs the full suite across every
sub-package.

## Cross-implementation interop

The test suites include vectors borrowed from other implementations so the
parsers and codecs aren't only validated against bytes we produced ourselves:

- `pkix` parses the live Let's Encrypt R10 intermediate CA (PEM embedded in
  `pkix/fixtures_test.mbt`) and round-trips it byte-stable.
- `pkcs8` parses the Ed25519 PKCS#8 v1 + v2 PEM fixtures from
  `RustCrypto/formats`, including the v2 "Curdle Chairs" attribute from
  RFC 8410 §10.3.
- `aead`, `ed25519`, `x25519`, `p256`, `p384`, `p521`, `secp256k1`, and `rsa`
  include Wycheproof or Wycheproof-derived vectors where the workspace has
  matching algorithm support.
- `jwt`, `jwe`, `cose`, `pkcs8`, `pbkdf2`, `scrypt`, and `hash` include
  reference or platform-oracle tests against external implementations.
- `pkix_verify` replays in-scope subsets of the C2SP/x509-limbo and Netflix
  BetterTLS certificate-path-validation suites (`testdata/x509-limbo`,
  `testdata/bettertls`, generated by `scripts/gen_x509_limbo.py`); the harness
  fails if any chain that should be rejected verifies.

## Git commit signing

Git's three `gpg.format` families are covered as verify-side building blocks:

| `gpg.format` | Format | Modules |
|---|---|---|
| `ssh` | SSHSIG-style armor | `git_object` + `ssh` + key primitives |
| `openpgp` | OpenPGP detached signature armor | `git_object` + `pgp` + `hash` |
| `x509` | CMS SignedData detached signature | `git_object` + `cms` + `pkix_verify` |

The usual flow is:

1. Read `git cat-file commit <rev>` bytes.
2. Parse the object with `@git_object.parse_signed_commit`.
3. Verify `signed.signature_armor` over `signed.signed_content` with `@ssh`,
   `@pgp`, or `@cms`.

SSH is intentionally a conservative SSHSIG-style subset, not an OpenSSH
compatibility claim. See [docs/GIT-SIGNING.md](docs/GIT-SIGNING.md) for
allowed_signers, OpenPGP, and X.509/CMS examples.

## Build

```
moon test                                       # all sub-packages
moon test --target all                          # wasm-gc + wasm + native
moon test -p mizchi/experimental_crypto/asn1    # single sub-package
moon bench --release -p mizchi/experimental_crypto/x25519
moon check --target all
```

The native backend uses a small C stub (`getrandom/getrandom_native.c`) that
selects `arc4random_buf` on macOS / *BSD, `getrandom(2)` on Linux, and
`BCryptGenRandom` on Windows.

## Performance baselines

Run on wasm-gc, release mode, on the author's machine
(`moon 0.1.20260522`). Reproduce with `moon bench --release -p
mizchi/<module>`:

| Operation | Time | Notes |
|---|---:|---|
| `asn1` encode flat SEQUENCE x100 | ~3.1 us | depth benchmarks use the enforced MAX_DEPTH=32 |
| `asn1` decode flat SEQUENCE x100 | ~2.2 us | |
| `crypto_bigint` 256-bit `pow_mod` | ~108-109 us | sparse and dense exponent classes |
| `crypto_bigint` 256-bit `inv_mod` | ~109-112 us | sparse and dense input classes |
| `aead` ChaCha20-Poly1305 seal 1 KiB | ~5.3 us | |
| `aead` AES-128-GCM seal 1 KiB | ~9.2 us | portable 4-bit Shoup GHASH; no hardware CLMUL |
| `x25519` ECDH | ~85 us | 10-limb Montgomery ladder |
| `p256` sign | ~2.0 ms | fixed-iteration sign-side scalar path |
| `p384` sign | ~5.2 ms | fixed-iteration sign-side scalar path |
| `secp256k1` sign | ~2.0 ms | fixed-iteration sign-side scalar path |
| `pbkdf2` HMAC-SHA256 c=1k dkLen=32 | ~542 us | |
| `pbkdf2` HMAC-SHA256 c=10k dkLen=32 | ~5.9 ms | |

For comparison, `dalek` / `RustCrypto` numbers are roughly an order of
magnitude faster than what's here today. The path to closing that gap is
documented per-module in the file headers (mostly: avoid per-op
`FixedArray::make` allocations, move to 5-limb radix-2^51 once MoonBit
exposes a 64×64 → 128 multiply primitive, and add SIMD on the native
backend where possible).

## Known limitations

These are intentional and called out in the source where they apply:

- **Not constant-time end-to-end.** `crypto_bigint`, RSA private modexp, and
  ECDSA sign-side scalar multiplication mostly use fixed-limb / fixed-iteration
  paths, Linux-native leakage smoke gates, and loose JS / wasm-gc / wasm
  backend smoke checks, but this is still not a constant-clock proof. P-521
  sign-side paths are wired into the leakage harness but still need repeated
  calibrated evidence before a measured-candidate claim. See
  [docs/CONSTANT_TIME.md](docs/CONSTANT_TIME.md).
- **Partial protocol coverage.** TLS 1.3, PKCS#12, Ed448 / X448, ML-KEM /
  ML-DSA, AES-GCM-SIV / AES-SIV, `age`, and EIP-712 / EIP-191 are not
  implemented.
- **Revocation scope is conservative.** OCSP and CRL parsing / verification
  exist, but unsupported delta / indirect / distribution-point semantics are
  rejected fail-closed rather than silently applied.
- **No GHASH carryless-multiplication intrinsic.** The `gcm` module uses a
  portable 4-bit Shoup table, not hardware CLMUL / SIMD.

## License

Apache-2.0. Some sub-package directories still carry their own `LICENSE`
file (a leftover from when each was a separate `moon new` module); the module
as a whole is Apache-2.0.

## Layout

```
.
├── moon.mod                # single module manifest (mizchi/experimental_crypto)
├── README.md               # this file
├── .gitignore
└── <subpkg>/
    ├── moon.pkg            # package imports, native stubs, target maps
    ├── <subpkg>.mbt        # main source
    ├── <subpkg>_test.mbt   # blackbox tests
    ├── <subpkg>_wbtest.mbt # whitebox tests (where useful)
    └── pkg.generated.mbti  # public API snapshot, regenerated by `moon info`
```

Sub-packages depend on each other by path in their `moon.pkg`
(`import { "mizchi/experimental_crypto/<dep>" }`); the import alias is the last
path segment, so `@asn1`, `@pkix`, … keep working unchanged. Because everything
is one module, there are no per-package `moon.mod` version pins anymore — only
the one external dependency (`moonbitlang/x`) is declared, in the root
`moon.mod`.

## Security Disclaimer ⚠️

This implementation of these cryptographic algorithms is provided without any
security endorsement or professional certification. The experimental_crypto
project should be considered:

- An educational reference implementation
- Experimental cryptography software
- Not reviewed by third-party security experts

### What review *has* happened

This is internal review only — it does not substitute for a professional audit:

- **Negative test corpus.** Each parser / verifier ships `ATTACK …` tests that
  pin reject behaviour (signature forgery, DER parser confusion, JWT algorithm
  confusion, CMS content-swap, padding edge cases). The X.509 path verifier is
  swept against the [x509-limbo](https://github.com/C2SP/x509-limbo) corpus
  (`scripts/gen_x509_limbo.py` in CI, `scripts/audit_x509_limbo.py` for the full
  ~2200-case one-shot) and every accepted reject case is documented as
  out-of-scope-by-design, with zero known false positives.
- **Verification-bypass review.** RSA PKCS#1 v1.5 verify is encode-then-compare
  (no DigestInfo parser to fool); ECDSA rejects `r,s ∉ [1,n-1]`; Ed25519 enforces
  canonical `S`; JWT binds `alg` to the key type and has no `alg=none` path; the
  PKIX chain validator is fail-closed (every failure `raise`s, the only success
  is falling through the whole pipeline). AEAD tags are compared in constant time
  and plaintext is withheld until the tag verifies.

### Before you use any of this in a real system

1. Read the source for the specific module and confirm it meets your threat
   model — **side-channel / timing resistance is not certified** (see
   [Known limitations](#known-limitations) and
   [docs/CONSTANT_TIME.md](docs/CONSTANT_TIME.md)).
2. Prefer a vetted library (`RustCrypto`, `dalek`, `BoringSSL`, …) wherever one
   exists for your protocol.
3. Commission an independent audit before depending on it for anything that
   protects keys, identities, or user data.
