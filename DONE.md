# Completed Work

Completed items moved out of `TODO.md` so the active backlog stays readable.

## Algorithm Coverage

| Item | Module | Commit |
|---|---|---|
| secp256k1 verify + sign (BIP-62 low-s default) | `secp256k1` | d3f8d7b |
| RSA-PSS (PS256/384/512) | `rsa` + `jwt` | d3f8d7b |
| PBES2 encrypted PKCS#8 + AES-CBC | `pkcs8` + `aead` | d3f8d7b |
| JWE (RFC 7516: dir / RSA-OAEP-256 / A256KW + A128/256GCM) | `jwe` | f66b7a1 |
| CBOR (RFC 8949 minimum viable) | `cose_cbor` | f66b7a1 |
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
| JWK parse / serialise / RFC 7638 thumbprint | `jwk` | ef4f3d0 |
| HPKE Mode_Base DHKEM(X25519, HKDF-SHA-256) + ChaCha20Poly1305 | `hpke` | ef4f3d0 |
| HOTP / TOTP (RFC 4226 / 6238) + provisioning URI | `totp` | ef4f3d0 |
| BLAKE2b in `@hash` (RFC 7693) | `hash` | ef4f3d0 |
| BLAKE3 in `@hash` (test_vectors.json verified) | `hash` | ef4f3d0 |
| HMAC-SHA-1 in `@hash` (unlocks HOTP) | `hash` | ef4f3d0 |
| `mizchi/cbor` namespace renamed to `mizchi/cose_cbor` | `cose_cbor` | 0d535ae |
| Post-sweep hardening (JWK RSA validation, PKIX strictness, etc.) | various | 98efbd2 |

## Formal Methods And Tooling

| Item | Module / Area | Commit |
|---|---|---|
| `mizchi/proofs` cross-cutting primitives (5 goals) | `proofs` | bde2bd8 |
| `pem/wrap` RFC 7468 section 3 line-cap invariant (1 goal) | `pem/wrap` | dfe490a |
| `aead/wrap` GHASH zero-pad + PKCS#7 pad-len (2 goals) | `aead/wrap` | a5ab414 |
| `hkdf/wrap` HKDF-Expand block count (1 goal) | `hkdf/wrap` | a5ab414 |
| `asn1/wrap` DER length-prefix size (1 goal) | `asn1/wrap` | a5ab414 |
| CVC5 + Alt-Ergo wired so modular postconditions discharge | toolchain | c6afd72 |
| All-nix solver stack (why3 1.7.2 from nixos-24.05, no opam) | toolchain | 3fe7803 |
| `flake.nix` for reproducible moon prove dev shell | tooling | 9a5df84 |
| `.envrc`, `proofs/setup.sh`, `proofs/prove.sh` | tooling | 9a5df84 / 3fe7803 |
| GitHub Actions CI on ubuntu-latest | CI | 7b9235d |
| Node.js 24-compatible action versions | CI | 0d996fc |
| `docs/` workspace summary | docs | 2a00219 |
| `derive(Show)` to `derive(Debug)` migration | workspace | 3fe7803 |
| `e.to_string()` / `repr(x)` to `@debug.to_string(x)` / `@debug.repr(x)` | workspace | 3fe7803 / 50048e6 |
| Experimental-status warning in every module README + moon.mod | workspace | 6fccbf7 |
| CI target matrix for `wasm-gc`, `native`, and `js`; `moon prove` separate | CI | done |

## Constant-Time / BigInt Reduction

- Move `crypto_bigint` modular add/sub/mul/pow and Montgomery `r2` reduction
  off the BigInt fallback onto fixed-limb code.
- Replace `crypto_bigint.inv_mod`'s BigInt-backed fallback with a limb-based
  odd-modulus binary-GCD path that rejects unsupported even moduli fail-closed.
- Replace the variable-iteration `crypto_bigint.inv_mod` loop with a
  fixed-iteration odd-modulus almost-inverse path.
- Keep BigInt only as a test oracle for 256-bit carries, operands wider than
  the modulus, multi-limb exponents, Montgomery `r2`, and modular inverses.
- Add a 32-bit-word native Montgomery multiplication path for odd moduli and
  route `Uint::pow_mod` / `Montgomery::{to_mont,from_mont,mul,pow}` through it.
- Route RSA PKCS#1 v1.5 / PSS sign-side private modexp through
  `crypto_bigint.Uint::pow_mod`, leaving BigInt for public verification and key
  parsing.
- Route JWE RSA-OAEP private unwrap modexp through `crypto_bigint.Uint::pow_mod`,
  leaving BigInt for public RSA-OAEP encryption and key parsing.
- Route P-256 / P-384 / secp256k1 final ECDSA nonce inverses through
  `crypto_bigint.Uint::inv_mod`, reducing one sign-side `@bigint.pow` use while
  leaving affine scalar multiplication as the remaining side-channel item.
- Document the exact terminology split in `docs/CONSTANT_TIME.md`: current
  code is fixed-limb / fixed-iteration and branchless-intended, not measured
  constant-clock.
- Add `crypto_bigint` sparse-vs-dense `moon bench` smoke targets for `pow_mod`
  and `inv_mod`; these are regression aids, not constant-time evidence.
- Add P-256 10-limb field add/sub/neg plus interim fixed-width
  mul/square/inversion helpers and BigInt-oracle whitebox tests. These helpers
  are not wired into scalar multiplication yet.
- Add P-256 projective point conversion, double/add, and a branchy scalar
  multiplication correctness baseline against the existing affine oracle.
- Add P-256 field and projective point conditional-select helpers as the
  groundwork for a fixed-iteration scalar multiplication path.
- Add a P-256 fixed-256-iteration scalar multiplication skeleton; keep it
  disconnected from signing because projective addition still branches on
  exceptional cases.
- Add P-256 homogeneous-projective complete addition, verify it against the
  affine oracle, and route sign-side base-point scalar multiplication away
  from affine `@bigint`.
- Add `crypto_bigint.Uint::ct_select` for cross-package branchless-intended
  field / point selection.
- Add P-384 crypto_bigint-backed homogeneous-projective complete addition and
  affine-oracle tests; leave scalar/sign wiring disconnected until the
  384-bit scalar loop has a faster reducer for JS.
- Move P-384 field operations into Montgomery form, add fixed-scalar oracle
  tests, and route P-384 sign-side base-point scalar multiplication plus
  public-key derivation away from affine `@bigint`.
- Add secp256k1 crypto_bigint-backed Montgomery-field complete addition,
  affine-oracle tests, and a minimal fixed-scalar oracle; leave sign wiring
  disconnected until the 256-bit scalar path is fast enough for JS.
- Add a reduced-input Montgomery multiplication path plus secp256k1
  fixed-limb add/sub helpers, then route secp256k1 sign-side base-point scalar
  multiplication and public-key derivation away from affine `@bigint`.
- Add sparse-vs-dense private-scalar `moon bench` smoke targets for P-256,
  P-384, and secp256k1 sign paths as pre-work for external leakage harnesses.
- Add a P-256 Montgomery-domain complete-addition fast path, route P-256
  sign-side scalar multiplication and public-key derivation through it, and
  bring P-256 sign benchmarks down to the same millisecond-scale band as
  secp256k1.
- Add `mizchi/leakage_harness`, a native main package with sparse-vs-dense
  class workloads for `crypto_bigint::{pow_mod,inv_mod}`, RSA PKCS#1 v1.5
  sign, JWE RSA-OAEP decrypt, and P-256/P-384/secp256k1 ECDSA sign. This is a
  measurement entry point, not constant-time proof or CI gating.

## Parser And Protocol Hardening

### ASN.1 / PEM / PKCS#8 / PKIX

- Reject non-canonical ASN.1 high-tag-number forms.
- Reject DER universal tag form mismatches such as constructed INTEGER.
- Decode multi-byte OID first subidentifiers and reject non-minimal encoding.
- Reject BIT STRING encodings whose unused tail bits are not zero.
- Validate PEM labels on decode and encode.
- Enforce schema-aware DER SET ordering in PKIX RDNs and PKCS#8 attributes.
- Tighten PKIX validity UTCTime / GeneralizedTime syntax.
- Reject non-positive PKIX serial numbers and duplicate optional fields.
- Validate context-specific / IMPLICIT BIT STRING tail padding at PKIX / PKCS#8.
- Reject duplicate PKCS#8 optional `attributes` and `publicKey` fields.
- Enforce generic DER SET / SET OF canonical ordering in the encoder.
- Tighten PrintableString alphabet + UTCTime / GeneralizedTime syntax.
- Add PEM -> ASN.1 -> PKCS#8 / PKIX integration fuzzing.
- Reject PKCS#8 PEM legacy `Proc-Type` / `DEK-Info` headers.
- Route RSA / Ed25519 / P-256 / P-384 `from_pkcs8_pem` through the hardened PKCS#8 PEM parser.
- Reject mismatched optional PKCS#8 v2 `publicKey` in RSA / Ed25519 / P-256 / P-384 loaders.
- Add PBES2 `id-scrypt` decryption for encrypted PKCS#8 and a Node.js
  `crypto.scryptSync` / AES-256-CBC oracle fixture.
- Reject recognised-but-unenforced critical PKIX extensions such as `certificatePolicies`, `policyConstraints`, `inhibitAnyPolicy`, critical EKU, and critical SAN gaps.
- Handle leading-dot DNS nameConstraints and reject unsupported top-level nameConstraints fields.

### SSH

- Document `ssh` as a conservative SSHSIG-style subset, not an OpenSSH-compatible verifier.
- Fail closed on `allowed_signers` `cert-authority`, `valid-after`, and `valid-before`.
- Parse comma-separated `allowed_signers` options without dropping `namespaces="..."`.
- Reject duplicate `namespaces` options instead of last-one-wins widening.
- Reject empty SSHSIG namespaces.
- Reject non-minimal SSH `mpint` encodings.
- Add structured fuzz / mutation tests for `allowed_signers`, SSHSIG envelopes, inner signature algorithms, and SSH `mpint` canonicality.
- Add strict SSHSIG armor decoder for trust decisions.
- Add high-level `verify_with_allowed_signers` regressions proving unsupported
  `cert-authority`, `valid-after`, and `valid-before` policy lines fail closed
  instead of authenticating a valid signature under unenforced policy.

### HPKE / JWK / TOTP / BLAKE3

- Check HPKE sequence exhaustion before AEAD Seal/Open.
- Validate HPKE AEAD context shape before nonce / AEAD calls.
- Reject invalid HPKE LabeledExpand output lengths.
- Reject invalid JWK RSA / EC / Ed25519 parameters and key mismatches.
- Treat JWK `oct` as private-only.
- Fail closed on invalid TOTP digits / step / skew.
- UTF-8 encode BLAKE3 derive-key contexts and pin the non-ASCII reference vector.

### JWT / OIDC / JOSE

- Compare JOSE `typ` values case-insensitively for both allow-list and specialised-token deny-list checks.
- Require the Back-Channel Logout event marker to be object-valued.
- Add strict OIDC ID Token / JARM option constructors that bind nonce / state by construction.
- Add strict JAR defaults requiring `exp` and fresh `iat`.
- Reject duplicate JSON object members at JWT / JWE / JWK trust boundaries before Map collapse.
- Recurse duplicate-member rejection into nested JWT objects such as DPoP `jwk` headers and self-issued `sub_jwk` claims.
- Reject non-canonical base64url pad-bit spellings at JWT / JWE / JWK trust boundaries.
- Reject malformed JWT `aud` arrays instead of matching one good string while ignoring non-string entries.
- Reject unsafe `kid` values: empty, non-printable, whitespace, and overlong.
- Enforce JWKS `key_ops` metadata for verification keys.
- Add RS384 / RS512 sign+verify roundtrips.
- Add RSA JWKS mapping coverage for RS384 / RS512 / PS384 / PS512.
- Add deterministic JWT / OIDC coverage for malformed headers, OIDC ID Token JWKS, nonce / `at_hash` / `c_hash`, RFC 7523 client assertions, DPoP, logout tokens, UserInfo, JAR, JARM, SIOP, nested encrypted ID Tokens, aggregated / distributed claims, Discovery, Federation, CIBA, and FAPI RFC 9068.
- Add offensive JWT / OIDC regressions for untrusted `jku` / embedded `jwk`, issuer and audience substitution, JAR / JARM mix-up, logout replay, nested token confusion, federation substitution, and CIBA substitution.
- Add malformed UTF-8 JWT header and signed payload fixtures for the decode
  catch arms.
- Add DPoP malformed embedded `jwk` header and claim-shape fixtures.

### COSE / CMS / OCSP / CRL / PGP / Git Objects

- Require CMS detached `signedAttrs` `contentType=id-data` and a unique `messageDigest`.
- Enforce CMS supported v1 SignedData field order.
- Require CMS `digestAlgorithms` to match the single SignerInfo digest.
- Reject embedded CMS CRLs until revocation semantics are implemented.
- Reject duplicate CMS signer certificates matching the same `SignerInfo.sid`.
- Reject unexpected CMS SignerInfo trailing fields except the standard unsignedAttrs slot.
- Enforce COSE_Key `alg` metadata matching the parsed key type.
- Enforce COSE_Key `key_ops` metadata permitting `verify`.
- Reject COSE_Sign1 unsupported `crit` headers in protected and unprotected maps.
- Add RFC 9052 COSE_Sign1 ES256 reference vector.
- Reject unsupported OCSP response / revocation extensions, critical or non-critical.
- Reject unsupported OCSP `ResponseData.version` values.
- Reject OCSP responses whose `producedAt` is in the future.
- Require OCSP high-level verification responses to include `nextUpdate`.
- Add `verify_with_nonce` and reject nonce-bearing OCSP responses unless the
  signed response nonce is explicitly bound to the request nonce.
- Require delegated OCSP responder certs to carry non-critical
  `id-pkix-ocsp-nocheck`; reject delegated responders whose revocation status
  would otherwise be unchecked.
- Add external OpenSSL OCSP fixtures for direct responder acceptance and
  delegated responder rejection without `id-pkix-ocsp-nocheck`.
- Add unsigned OCSPRequest construction with SHA-1 / SHA-256 CertID selection
  and non-empty request nonce extension support.
- Add OCSP HTTP POST request metadata (`application/ocsp-request` /
  `application/ocsp-response`) without performing network I/O.
- Reject OCSP request construction and response verification when the supplied
  issuer cert is not named as the target certificate issuer.
- Reject unsupported CRL / CRL-entry extensions instead of ignoring scope, delta, or indirect-CRL semantics.
- Reject unsupported CRL `TBSCertList.version` values.
- Require high-level CRL verification to include `nextUpdate`.
- Pin CRL fail-closed behavior for `deltaCRLIndicator`,
  `issuingDistributionPoint`, and `certificateIssuer` entry extensions.
- Validate accepted `cRLNumber` extensions as non-critical DER INTEGER values.
- Add external OpenSSL CRL fixture with `cRLSign` issuer key usage and revoked serial lookup.
- Add cross-format mutation fuzzing that feeds changed CMS SignedData through
  `cms -> pkix -> pkix_verify`, and changed OCSP / CRL fixtures through their
  high-level verification APIs, asserting mutated trust objects never
  authenticate.
- Reject PGP detached signature armor with anything other than exactly one Signature packet.
- Reject non-`SIGNATURE` armor labels and unsupported critical PGP signature subpackets.
- Fail closed on critical PGP issuer Key ID / issuer fingerprint subpackets until key binding exists.
- Reject PGP canonical-text signatures in the binary detached verifier.
- Enforce RFC 9580 hash-specific PGP v6 salt lengths on parse / verify / sign.
- Validate legacy PGP EdDSA public-key Ed25519 curve OID.
- Reject non-`PUBLIC KEY BLOCK` armor labels in PGP public-key parsing.
- Add PGP sign-side gpg interop for v4 Ed25519 by exporting a minimal
  transferable public key, embedding issuer metadata in generated detached
  signatures, and checking the result with `gpg --verify`.
- Add signed git tag-object coverage.
- Keep `parse_signed_commit` commit-only; reject tag content and raw tag objects.
- Keep duplicate `gpgsig` and body-only `gpgsig` rejection tests.

## Reference Tests And Fuzzing

- Add JWK -> JWT -> JWE cross-format fuzz covering JWKS key selection, signed JWT verification, and JWE wrapping.
- Add RFC 7520 `dir` + `A128GCM` compact JWE decrypt vector.
- Keep real Let's Encrypt R10 / ISRG Root X1 reference coverage in `pkix_verify`.
- Add libsodium XChaCha20-Poly1305 no-AAD reference vector for `naclbox.secretbox`.
- Add duplicate / non-canonical PHC parameter attack tests for Argon2 / scrypt.
- Reject duplicate PBKDF2 `keyLength` / `prf` fields and malformed PRF parameters in PBES2.
- Implement PBKDF2-HMAC-SHA1 / SHA384 / SHA512 and cover with reference vectors.
- Accept PBES2 PRFs `hmacWithSHA1`, `hmacWithSHA384`, and `hmacWithSHA512`.
- Add AES-192-CBC key schedule / CBC vectors and PBES2 decrypt coverage.
