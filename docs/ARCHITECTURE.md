# Architecture

`mizchi/moonbit-crypto` is a `moon.work` workspace of **32 modules**, each
solving one RFC-level concern. Modules depend only on `moonbitlang/core`,
`moonbitlang/x/crypto`, and each other.

## Dependency layers

```
                     ┌────────────────────────────────────┐
        Layer 5      │  jwt   jwe   pgp   ssh   cms       │ — JOSE / git signing
        applications │  git_object   ocsp   crl           │   formats
                     └─────────┬──────────────────┬───────┘
                               │                  │
                     ┌─────────┴──────┐ ┌────────┴────────┐
        Layer 4      │ pkix_verify    │ │ bip32   bip39   │ — chain validation,
        verifiers    │ (chain walk)   │ │ naclbox cose    │   HD wallets, COSE
                     └────┬────┬──────┘ └─────────────────┘
                          │    │
                     ┌────┴────┴──────────────────────────┐
        Layer 3      │ p256  p384  secp256k1  ed25519     │ — signature
        signing      │ x25519  rsa  (ECDH, sign + verify) │   primitives
                     └────┬────────────────┬──────────────┘
                          │                │
                     ┌────┴────────────────┴──────────────┐
        Layer 2      │ hash    aead    pkix               │ — hashes, AEAD,
        primitives   │ pkcs8   pem     pbkdf2             │   cert/KDF parsers
                     │ scrypt  argon2  hkdf               │
                     └────┬────────────────┬──────────────┘
                          │                │
                     ┌────┴────────────────┴──────────────┐
        Layer 1      │ asn1   cose_cbor   crypto_bigint   │ — encoding +
        encoding     │ getrandom                          │   foundations
                     └────────────────────────────────────┘

        Verification │ proofs                             │ — proof-carrying
        (sidecar)    │ (moon prove + Why3 + Z3)           │   leaf primitives
                     └────────────────────────────────────┘
```

## Module catalogue

### Layer 1 — encoding & foundations

| Module | Spec | Role |
|---|---|---|
| `asn1` | X.690 (DER) / X.680 | Strict canonical DER encoder + decoder. MAX_DEPTH=32 on both ends. Rejects tag aliases, canonical INTEGER / BIT STRING / OID / SET / PrintableString / time violations. |
| `cose_cbor` | RFC 8949 | CBOR major types 0..7 + tagged values. Floats always 8-byte. Used by COSE. Renamed from `cbor` to free the `mizchi/cbor` namespace for the upstream package. |
| `crypto_bigint` | (Rust crypto-bigint shape) | Fixed-limb unsigned integers, modular add/sub/mul/pow, odd-modulus Montgomery pow, and fixed-iteration odd-modulus inverse. BigInt is kept only in tests as an oracle. Branchless/fixed-iteration discipline is intended but still needs external leakage measurement before production constant-time claims. See `CONSTANT_TIME.md`. |
| `getrandom` | (target-specific) | CSPRNG bridge: `crypto.getRandomValues` on JS, `arc4random_buf` / `getrandom(2)` / `BCryptGenRandom` on native. |

### Layer 2 — primitives

| Module | Spec | Role |
|---|---|---|
| `hash` | FIPS 180-4 + RFC 2104 / 4634 / ISO 10118-3 + BLAKE specs | SHA-1, SHA-256/384/512, RIPEMD-160, HASH160, HMAC-SHA-256/384/512, BLAKE2b, BLAKE3 keyed / XOF / derive-key (UTF-8 context), ct_eq |
| `aead` | RFC 8439 + NIST SP 800-38D | ChaCha20-Poly1305 (5-limb Poly1305), XChaCha20-Poly1305, AES-128/256-GCM, AES-128/256-CBC (Shoup 4-bit GHASH, T-table AES) |
| `pkix` | RFC 5280 | X.509 v3 certificate parser + serialiser. Byte-stable DER round-trip, with strict serial, validity-time, duplicate optional field, RDN SET order, and IMPLICIT BIT STRING padding checks. |
| `pkcs8` | RFC 5208 / 5958 + RFC 8018 | PrivateKeyInfo + EncryptedPrivateKeyInfo. PBES2 decrypt (PBKDF2-HMAC-SHA-256 + AES-128/256-CBC). Rejects duplicate optional fields and non-canonical attributes/publicKey encodings. |
| `pem` | RFC 7468 | PEM I/O. Strict (64-char) emit; lax decode with line cap (8 KiB) + total cap (16 MiB). Labels validated on decode/encode. |
| `hkdf` | RFC 5869 | HKDF-Extract + Expand on HMAC-SHA-256. |
| `pbkdf2` | RFC 8018 | PBKDF2-HMAC-SHA-256 with ipad/opad pre-compression for the inner loop. |
| `scrypt` | RFC 7914 | Salsa20/8 + BlockMix + ROMix. PHC string encode/verify. |
| `argon2` | RFC 9106 | Argon2d/i/id; BLAKE2b self-impl; PHC string encode/verify. |

### Layer 3 — signature & ECDH primitives

| Module | Spec | Role |
|---|---|---|
| `ed25519` | RFC 8032 | Ed25519 sign + verify (with `verify_strict`). SHA-512 self-impl in module. Edwards curve via @bigint (TODO: 10-limb). |
| `x25519` | RFC 7748 | X25519 ECDH. 10-limb radix-2^25.5 Montgomery ladder; ~90µs/operation. Small-subgroup defence. |
| `p256` | NIST FIPS 186-5, SEC 1 | ECDSA-SHA-256 verify + sign (RFC 6979 deterministic). Sign-side base-point multiplication and final nonce inverse route through fixed-limb paths; public verify remains affine `@bigint`. PKCS#8 loader (curve-OID checked). |
| `p384` | NIST FIPS 186-5 | ECDSA-SHA-384. Sign-side base-point multiplication and final nonce inverse route through fixed-limb paths; public verify remains affine `@bigint`. |
| `secp256k1` | SEC 2 §2.4.1 | Bitcoin / Ethereum curve. ECDSA + RFC 6979 + BIP-62 low-s by default; sign-side base-point multiplication and final nonce inverse route through fixed-limb paths; public verify remains affine `@bigint`. `sign_no_low_s` for pre-BIP-62 callers. `PublicKey::to_compressed` for BIP-32. |
| `rsa` | RFC 8017 | RSA PKCS#1 v1.5 + RSA-PSS (MGF1-SHA-2{56,384,512}). Sign + verify. Sign-side private modexp routes through `crypto_bigint`; public verify remains `@bigint.pow`. PKCS#1 / SPKI / PKCS#8 loaders. |

### Layer 4 — composers / verifiers

| Module | Spec | Role |
|---|---|---|
| `pkix_verify` | RFC 5280 §6 | X.509 chain validation. Ed25519, RSA-SHA256, ECDSA-SHA-2{56,384}. Critical-extension recognition, keyUsage.keyCertSign enforcement on issuers, pathLenConstraint, nameConstraints (DNS subtree intersection), optional required EKU. |
| `naclbox` | libsodium `crypto_box_curve25519xchacha20poly1305` | Curve25519 + XChaCha20-Poly1305. Composes `x25519` + `aead`. |
| `hpke` | RFC 9180 | Mode_Base DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305. Sequence exhaustion checked before AEAD; caller supplies fresh ephemeral `sk_e`. |
| `bip39` | BIP-39 | English mnemonic ↔ entropy + PBKDF2-HMAC-SHA-512 seed. |
| `bip32` | BIP-32 | Hierarchical-deterministic key derivation on secp256k1. Master + CKDpriv + neuter + `derive_path("m/44'/0'/0'/0/0")`. |
| `cose` | RFC 9052 | COSE_Sign1 verify (ES256/384, EdDSA, RS256), COSE_Key parser, WebAuthn attestation convenience. |

### Layer 5 — application formats

| Module | Spec | Role |
|---|---|---|
| `jwt` | RFC 7515 / 7519 / 7518 | JWS / JWT sign + verify. HS256, EdDSA, RS256, ES256/384, PS256/384/512. Rejects `crit` and `b64` headers. |
| `jwe` | RFC 7516 / 7518 | JWE compact serialisation. dir / RSA-OAEP-256 / A256KW + A128/256GCM. |
| `jwk` | RFC 7517 / 7518 / 7638 / 8037 | JWK parse / serialise / thumbprint. Validates RSA parameters and EC / Ed25519 private-public consistency; `oct` is private-only. |
| `totp` | RFC 4226 / 6238 | HOTP / TOTP generation, verification, and provisioning URI. Rejects invalid digit / step / skew parameters fail-closed. |
| `pgp` | RFC 9580 (+ RFC 4880 backward compat) | OpenPGP v4 + v6 detached signature verify + sign. Ed25519, RSA, ECDSA P-256/384. |
| `ssh` | SSHSIG-style subset | SSHSIG armor sign + verify. Ed25519, ECDSA P-256/384, RSA-SHA-2-256/512. Conservative `allowed_signers`-style parser. |
| `cms` | RFC 5652 | CMS SignedData detached verify. SignerInfo with IssuerAndSerialNumber match. `verify_with_chain` composes with `pkix_verify`. |
| `git_object` | git format | Commit / tag signature extraction. Strips `gpgsig` header for canonical signed bytes. |
| `ocsp` | RFC 6960 | OCSP response parse + verify. Direct-signed and delegated-responder paths. SHA-1 and SHA-256 CertIDs. |
| `crl` | RFC 5280 §5 | CRL parse + verify + `is_revoked`. |

## Design conventions

- **Strict canonical encoding everywhere**: DER decoder rejects non-canonical
  INTEGER, tag aliases, constructed/primitive universal tag mismatches, OID
  base-128 aliases / arc overflow, non-zero BIT STRING tail padding,
  non-canonical SET ordering, invalid PrintableString characters, invalid
  UTCTime / GeneralizedTime syntax, and trailing bytes. PEM (strict mode)
  rejects long lines and missing padding; both PEM decoders validate labels.
  PKIX and PKCS#8 add schema-aware checks for duplicate optional fields and
  context-specific BIT STRING padding.
- **Verify-first APIs**: every signature/hash primitive ships verify before
  sign. Sign was added later for ECDSA / RSA after the security audit.
- **RFC-driven error types**: each module has its own `*Error` suberror enum
  with named variants (e.g. `KeyUsageMissingCertSign`, `MessageDigestMismatch`)
  so callers can branch on policy violations cleanly.
- **No silent fallbacks**: unsupported algorithms / curves / hashes raise
  named errors. Bare `rsaEncryption` signature OIDs in CMS pull the hash from
  `digestAlgorithm` and cross-check.
- **Caller-supplied randomness for sign**: ECDSA uses RFC 6979 deterministic
  nonces. RSA-PSS for JWT uses sLen=0 (deterministic) because no vetted RNG
  is exposed at the JWT layer; callers needing RFC 7518 interop call
  `@rsa.sign_pss` directly.
- **Const-time gaps documented**: every remaining variable-time sign path has a
  doc comment marking the side-channel. `crypto_bigint` now uses fixed-limb /
  fixed-iteration code for modular arithmetic, but external leakage
  measurement is still required before treating it as production constant-time.
