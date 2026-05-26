# Module Reference

Quick-look reference for every module in the workspace. Each entry lists
the spec, the test count at the time of writing, and the headline API.
See per-module source for full details.

## Encoding / foundations

### `mizchi/asn1`
**RFC**: X.690 DER + X.680 ASN.1. **Tests**: ~80.

```moonbit
@asn1.decode_der(bytes : Bytes) -> Element raise Asn1Error
@asn1.encode_der(elem : Element) -> Bytes
@asn1.ObjectIdentifier::from_arcs(arcs)           // abort on bad arc
@asn1.ObjectIdentifier::from_arcs_checked(arcs)   // Result-style
```

Strict canonical DER. MAX_DEPTH=32 on decoder AND encoder. Rejects
non-canonical INTEGER, BIT STRING `unused_bits > 7`, trailing bytes
after the outer element, OID arc-overflow.

### `mizchi/cbor`
**RFC**: 8949 minimum-viable. **Tests**: 41.

> **Note**: the workspace also depends on `mizchi/cbor` from mooncakes;
> the in-tree module is currently unused upstream. Reconsider integration.

### `mizchi/crypto_bigint`
Wrapper around `@bigint`. Limb-based rewrite is the prerequisite for
constant-time sign-side operations.

### `mizchi/getrandom`
CSPRNG bridge. Platform backends: `crypto.getRandomValues` on JS,
`arc4random_buf` / `getrandom(2)` / `BCryptGenRandom` on native.

## Hashes + AEAD

### `mizchi/hash`
**Tests**: 24.

```moonbit
@hash.sha1 / sha256 / sha384 / sha512 / ripemd160
@hash.hash160(b) = ripemd160(sha256(b))                // for BIP-32
@hash.hmac_sha256 / hmac_sha384 / hmac_sha512
@hash.ct_eq(a : Bytes, b : Bytes) -> Bool              // constant-time
```

### `mizchi/aead`
**RFC**: 8439 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM). **Tests**: 80+.

```moonbit
@aead.chacha20_poly1305_seal / open
@aead.xchacha20_poly1305_seal / open
@aead.aes_gcm_seal / open                              // 128 + 256
@aead.aes_cbc_encrypt / decrypt                        // 128 + 256
@aead.aes_block_encrypt / decrypt                      // single AES block
```

Poly1305 uses 5-limb radix-2^26 (3.7× over @bigint).
AES uses T-table forward + the Equivalent-Inverse-Cipher inverse path.

## KDFs

### `mizchi/hkdf`, `mizchi/pbkdf2`, `mizchi/scrypt`, `mizchi/argon2`

```moonbit
@hkdf.extract_and_expand(salt, ikm, info, length, hash)
@pbkdf2.pbkdf2(hash, password, salt, iters, dk_len)
@scrypt.scrypt(password, salt, n, r, p, dk_len)        // PHC string roundtrip
@argon2.argon2(variant, password, salt, ...)           // d / i / id
```

All four enforce parameter bounds: HKDF L ≤ 255*hashLen, PBKDF2
iters ≥ 1, scrypt log_n ≤ 24 with UInt64 multiply-check, Argon2
RFC 9106 §4.1 lower/upper bounds.

## X.509 / PKCS#8 / PEM

### `mizchi/pkix`
X.509 v3 parser + serialiser. Byte-stable DER round-trip. Used by
`pkix_verify`, `cms`, `ocsp`, `crl`.

### `mizchi/pkcs8`
**Tests**: ~22 (incl. PBES2).

```moonbit
@pkcs8.parse_der / parse_pem -> PrivateKeyInfo
@pkcs8.parse_encrypted_der / parse_encrypted_pem -> EncryptedPrivateKeyInfo
@pkcs8.decrypt(enc, password) -> PrivateKeyInfo        // PBES2 + PBKDF2 + AES-CBC
@pkcs8.decrypt_pem(pem, password) -> PrivateKeyInfo
```

PBES2 supports PBKDF2-HMAC-SHA-256 + AES-128/256-CBC.
HMAC-SHA-1/384/512 and AES-192 currently rejected (`UnsupportedKdf` /
`UnsupportedCipher`).

### `mizchi/pem`
RFC 7468 strict + lax. Lax decode enforces a 8 KiB per-line cap on top
of the existing 16 MiB total cap.

## Signature primitives

### `mizchi/ed25519`
**RFC**: 8032. **Tests**: 30+.

```moonbit
@ed25519.PrivateKey::from_seed(b)
@ed25519.PrivateKey::from_pkcs8_pem(s)
sk.sign(message)
@ed25519.PublicKey::verify / verify_strict             // verify_strict rejects S ≥ L
```

### `mizchi/x25519`
**RFC**: 7748. **Tests**: 30+. 10-limb radix-2^25.5 Montgomery ladder.
Small-subgroup defence (all-zero shared secret raises).

### `mizchi/p256`, `mizchi/p384`
**RFC**: FIPS 186-5, SEC 1, RFC 6979. **Tests**: 19/17.

```moonbit
@p256.PublicKey::from_uncompressed / from_spki_der
@p256.PrivateKey::from_bytes / from_pkcs8_pem          // curve-OID checked
sk.sign(message, format=Raw | Der)                     // RFC 6979 deterministic
@p256.verify(pk, message, sig, format)
```

P-256 with SHA-256, P-384 with SHA-384. Sign side is variable-time on
the secret nonce; documented.

### `mizchi/secp256k1`
**Spec**: SEC 2 §2.4.1. **Tests**: 25.

```moonbit
@secp256k1.PrivateKey::from_bytes(b)
sk.sign(message)                                       // RFC 6979 + BIP-62 low-s default
sk.sign_no_low_s(message)
@secp256k1.PublicKey::to_compressed(self) -> Bytes     // 33-byte 02/03||X
```

Verify is permissive on high-s per FIPS 186-5; BIP-66 / EIP-2 strict
rejection is the caller's job.

### `mizchi/rsa`
**RFC**: 8017. **Tests**: 31.

```moonbit
@rsa.RsaPublicKey::from_pkcs1_der / from_spki_der
@rsa.RsaPrivateKey::from_pkcs1_der / from_pkcs8_pem
pk.verify(message, sig, HashAlg::Sha256/384/512)        // PKCS#1 v1.5
sk.sign(message, hash)                                  // PKCS#1 v1.5
pk.verify_pss(message, sig, hash, salt_len=hLen)        // PSS
sk.sign_pss(message, hash, salt)                        // PSS
```

## Composers / chain verifiers

### `mizchi/pkix_verify`
**RFC**: 5280 §6 chain validation. **Tests**: 24+.

```moonbit
@pkix_verify.verify_certificate(cert, issuer_pubkey, now)
@pkix_verify.verify_chain(leaf, intermediates, anchor_pk, now)
@pkix_verify.verify_chain_with_options(..., VerifyChainOptions {
  required_eku : @asn1.ObjectIdentifier?
})
```

Enforces critical-extension recognition, keyUsage.keyCertSign on
issuers, pathLenConstraint, DNS nameConstraints (intersection down the
chain), optional caller-supplied required EKU, strict UTCTime /
GeneralizedTime format, outer/inner signature_algorithm cross-check.

### `mizchi/naclbox`
libsodium-compatible `crypto_box_curve25519xchacha20poly1305`.

### `mizchi/bip39` + `mizchi/bip32`
BIP-39 mnemonic + BIP-32 HD wallet on secp256k1.

```moonbit
@bip39.entropy_to_mnemonic / mnemonic_to_entropy
@bip39.mnemonic_to_seed(mnemonic, passphrase="")
@bip32.master_from_seed(seed)
@bip32.derive_path(parent, "m/44'/0'/0'/0/0")
```

BIP-32 CKDpub for non-hardened indices is a stub; needs a public
point-add on `@secp256k1.PublicKey`.

### `mizchi/cose`
**RFC**: 9052 minimum-viable. **Tests**: 11.

```moonbit
@cose.verify_sign1(cose_sign1_bytes, payload, key, external_aad=b"")
@cose.parse_cose_key(cbor_bytes) -> CoseKey
@cose.parse_attestation_object(cbor) -> ...            // WebAuthn convenience
```

Reuses the wire bytes of `protected` per RFC 9052 §4.4 step 4.

## Application formats

### `mizchi/jwt`
**RFC**: 7515 / 7518 / 7519. **Tests**: 36.

Supported algorithms: HS256, EdDSA, RS256, ES256, ES384,
PS256/384/512. Rejects `alg:none`, `crit`, `b64` headers.

### `mizchi/jwe`
**RFC**: 7516 / 7518. **Tests**: 8.

`alg`: dir, RSA-OAEP-256, A256KW. `enc`: A128GCM, A256GCM. RSA-OAEP
unwrap is Manger-attack-shaped (single AuthenticationFailed for all
validation failures).

### `mizchi/pgp`
**RFC**: 9580 (with RFC 4880 backward compat). **Tests**: 15.

```moonbit
@pgp.parse_pubkey_armor(armor) -> PgpPublicKeyPacket
@pgp.verify_armor(sig_armor, message, pubkey)          // v4 + v6
@pgp.sign_armor(privkey, message, version=4|6)
```

v4 + v6 packets. Ed25519 (algo 22 v4 + algo 27 v6), RSA, ECDSA P-256/384.

### `mizchi/ssh`
**Spec**: OpenSSH PROTOCOL.sshsig. **Tests**: 23.

```moonbit
@ssh.parse_ssh_pubkey_text(line)
@ssh.verify_armor / verify_armor_anonymous / verify_armor_with
@ssh.sign_armor_with(privkey : SshPrivateKey, message, namespace="git")
@ssh.parse_allowed_signers(text)
@ssh.verify_with_allowed_signers(text, principal, armor, message)
```

Ed25519, ECDSA P-256/384, RSA (rsa-sha2-256/512). Plain `ssh-rsa` (SHA-1)
deliberately rejected.

### `mizchi/cms`
**RFC**: 5652. **Tests**: 7.

```moonbit
@cms.parse_signed_data(der) -> CmsSignedData
@cms.verify_detached(sd, message)
@cms.verify_with_chain(sd, message, anchor_pk, now)
```

`SignerIdentifier` parsed for `IssuerAndSerialNumber`;
`[0] subjectKeyIdentifier` raises `UnsupportedSid`.

### `mizchi/git_object`
git commit / tag signature extraction.

```moonbit
@git_object.parse_signed_commit(commit_bytes) -> SignedCommit
```

Strips `gpgsig` (and `gpgsig-sha256`) headers; rejects multi-gpgsig.

### `mizchi/ocsp`
**RFC**: 6960. **Tests**: 10.

```moonbit
@ocsp.parse_response(der) -> OcspResponse
@ocsp.verify(der, cert, issuer_cert, now) -> CertStatus
```

`CertStatus = Good | Revoked(time, reason) | Unknown`. Direct-signed
and delegated-responder paths. SHA-1 + SHA-256 CertID hashes.

### `mizchi/crl`
**RFC**: 5280 §5. **Tests**: 9.

```moonbit
@crl.parse(der) -> Crl
@crl.verify(der, issuer_cert, now) -> Crl
@crl.is_revoked(crl, serial) -> Bool
```
