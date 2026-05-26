# Known Issues / TODO

Status of `mizchi/moonbit-crypto` after the formal-methods +
CI + experimental-status sweep (HEAD `6fccbf7`).

## Closed

### Algorithm coverage (T1 / T2)

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

### JWK + HPKE + TOTP + hash sweep

| Item | Module | Commit |
|---|---|---|
| JWK parse / serialise / RFC 7638 thumbprint | `jwk` | ef4f3d0 |
| HPKE Mode_Base DHKEM(X25519, HKDF-SHA-256) + ChaCha20Poly1305 | `hpke` | ef4f3d0 |
| HOTP / TOTP (RFC 4226 / 6238) + provisioning URI | `totp` | ef4f3d0 |
| BLAKE2b in `@hash` (RFC 7693) | `hash` | ef4f3d0 |
| BLAKE3 in `@hash` (test_vectors.json verified) | `hash` | ef4f3d0 |
| HMAC-SHA-1 in `@hash` (unlocks HOTP) | `hash` | ef4f3d0 |
| `mizchi/cbor` namespace renamed to `mizchi/cose_cbor` | `cose_cbor` | 0d535ae |
| Post-sweep hardening (JWK RSA validation, PKIX strictness, etc.) | various | 98efbd2 |

### Formal methods (`moon prove` + Why3)

| Item | Module | Commit |
|---|---|---|
| `mizchi/proofs` cross-cutting primitives (5 goals) | `proofs` | bde2bd8 |
| `pem/wrap` RFC 7468 §3 line-cap invariant (1 goal) | `pem/wrap` | dfe490a |
| `aead/wrap` GHASH zero-pad + PKCS#7 pad-len (2 goals) | `aead/wrap` | a5ab414 |
| `hkdf/wrap` HKDF-Expand block count (1 goal) | `hkdf/wrap` | a5ab414 |
| `asn1/wrap` DER length-prefix size (1 goal) | `asn1/wrap` | a5ab414 |
| CVC5 + Alt-Ergo wired so modular postconditions discharge | toolchain | c6afd72 |
| All-nix solver stack (why3 1.7.2 from nixos-24.05, no opam) | toolchain | 3fe7803 |

10 goals discharged total via `Z3 → CVC5 → Alt-Ergo` strategy.

### Tooling / reproducibility

| Item | Commit |
|---|---|
| `flake.nix` for reproducible moon prove dev shell | 9a5df84 |
| `.envrc` (direnv) + `proofs/setup.sh` + `proofs/prove.sh` | 9a5df84 / 3fe7803 |
| GitHub Actions CI (`.github/workflows/ci.yml`) on ubuntu-latest | 7b9235d |
| Node.js 24-compatible action versions (`checkout@v6` etc.) | 0d996fc |
| `docs/` workspace summary (ARCHITECTURE, MODULES, SECURITY, GIT-SIGNING) | 2a00219 |

### Workspace-wide migrations

| Item | Commit |
|---|---|
| `derive(Show)` → `derive(Debug)` across all suberror / enum types | 3fe7803 |
| `e.to_string()` / `repr(x)` → `@debug.to_string(x)` / `@debug.repr(x)` | 3fe7803 / 50048e6 |
| Experimental-status warning in every module README + moon.mod | 6fccbf7 |

### ASN.1 / PEM security review follow-up

- [x] Reject non-canonical ASN.1 high-tag-number forms.
- [x] Reject DER universal tag form mismatches (constructed INTEGER etc.).
- [x] Decode multi-byte OID first subidentifiers and reject non-minimal encoding.
- [x] Reject BIT STRING encodings whose unused tail bits are not zero.
- [x] Validate PEM labels on decode and encode.
- [x] Enforce schema-aware DER SET ordering in PKIX RDNs and PKCS#8 attributes.
- [x] Tighten PKIX validity UTCTime / GeneralizedTime syntax.
- [x] Reject non-positive PKIX serial numbers and duplicate optional fields.
- [x] Validate context-specific / IMPLICIT BIT STRING tail padding at PKIX / PKCS#8.
- [x] Reject duplicate PKCS#8 optional `attributes` and `publicKey` fields.
- [x] Enforce generic DER SET / SET OF canonical ordering in the encoder.
- [x] Tighten PrintableString alphabet + UTCTime / GeneralizedTime syntax.
- [x] Integration fuzzing across PEM → ASN.1 → PKCS#8 / PKIX boundaries.

### SSH security review follow-up

- [x] Document `ssh` as a conservative SSHSIG-style subset.
- [x] Fail closed on `allowed_signers` `cert-authority` / `valid-after` /
  `valid-before` until certs and time-aware verification are implemented.
- [x] Parse comma-separated `allowed_signers` options without dropping
  `namespaces="..."` constraints.
- [x] Reject empty SSHSIG namespaces.
- [x] Reject non-minimal SSH `mpint` encodings.
- [x] Structured fuzz / mutation tests for `allowed_signers`, SSHSIG envelopes,
  inner signature algorithms, and SSH `mpint` canonicality.

### HPKE / JWK / TOTP / BLAKE3 follow-up

- [x] Check HPKE sequence exhaustion before AEAD Seal/Open.
- [x] Validate HPKE AEAD context shape before nonce / AEAD calls.
- [x] Reject invalid HPKE LabeledExpand output lengths.
- [x] Reject invalid JWK RSA / EC / Ed25519 parameters and key mismatches.
- [x] Treat JWK `oct` as private-only.
- [x] Fail closed on invalid TOTP digits / step / skew.
- [x] UTF-8 encode BLAKE3 derive-key contexts (non-ASCII reference vector pinned).

## Still open

### Algorithm gaps — Tier 1

- **TLS 1.3 client**: handshake + key schedule (HKDF-Expand-Label) +
  record layer. All cryptographic primitives are already here.

### Algorithm gaps — Tier 2 / 3

- **BIP-32 CKDpub for non-hardened indices**: needs a public point-add
  API on `@secp256k1.PublicKey`. Hardened path + neuter already work.
- **PGP v6 real-gpg fixture**: blocked on GnuPG ≥ 2.4.9 emitting v4 by
  default. Cross-test once rpgpie / rsop / a v6-capable gpg becomes
  available.
- **PGP v6 caller-supplied salt** in `sign_armor` (currently empty;
  RFC requires ≥16 bytes for production).
- **PBES2 HMAC-SHA1 / SHA-384 / SHA-512 PRF support** in `@pkcs8`
  (currently rejects with `UnsupportedKdf`).
- **AES-192-CBC** in `@aead.aes_cbc` (needs a third branch in
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
- **`age`** file encryption format.
- **EIP-712 / EIP-191** structured Ethereum signing helpers.

### SSH follow-up still open

- [x] Strict SSHSIG armor decoder for trust decisions. Current decoder is
  intentionally lax about surrounding whitespace.
- [ ] Explicit SSH certificate support before accepting `cert-authority`.
- [ ] Time-aware allowed_signers API before accepting
  `valid-after` / `valid-before`.

### Security gaps (no exploit, documented in source)

- **ECDSA / RSA sign side-channel**: `scalar_mult` and `@bigint.pow` are
  variable-time on the secret. Doc-commented in each `PrivateKey::sign`
  (p256/p384/secp256k1/rsa). Fix needs constant-time scalar mult +
  modexp, which in turn needs `crypto_bigint` rewritten as a real
  limb-based implementation.
- [x] **JWT `kid` not sanitised**: verification and JWKS selection now reject
  empty, non-printable, whitespace, and overlong `kid` values before returning
  or matching them.
- [x] **PKCS#8 v2 publicKey consistency**: a v2 record with a `[1]` field
  whose contents don't match the algorithm OID's public-key shape is
  rejected at parse time for known RSA / EC / RFC 8410 key shapes.
- **PSS RNG-backed sign in JWT**: PS256/384/512 currently uses
  deterministic PSS (sLen = 0) since the workspace has no vetted RNG
  at the JWT layer. RFC 7518 mandates sLen = hLen; callers needing
  full interop call `@rsa.sign_pss` directly with a freshly-sampled
  salt. Documented.

### Formal methods — incremental work

- **Block-alignment goals timed out on Z3** are now valid under CVC5;
  if Why3 1.7.2 ever recognises Z3 4.16 / CVC5 1.3 natively, the
  `partial_prover` shim in `proofs/why3.conf` can be dropped.
- More proof targets to pull in: `pbkdf2` block count, `argon2` memory
  alignment, `bip32` `is_hardened` predicate, `crypto_bigint` `limb_count`,
  `totp` time-bucket monotonicity. Same per-library wrap-package pattern.
- `ct_select` bitmask form (`(mask & a) | (~mask & b)`) blocked on
  `moon prove` lowering `&` / `|` / `lnot` to a bitvector theory. Only
  the arithmetic form `b + mask * (a - b)` discharges today.

### Test coverage / robustness

- [x] **JWT / OIDC coverage sweep**: deterministic security regression
  tests now cover malformed `kid` / JOSE headers, OIDC ID Token JWKS
  resolution and algorithm allow-lists, nonce / `at_hash` / `c_hash` /
  `auth_time` / `acr` binding failures, RFC 7523 client assertion JWKS,
  DPoP nonce / `ath` / `jkt` / alg policy failures, logout-token JWKS
  and freshness, UserInfo/JAR/JARM, Self-Issued OP, nested encrypted ID
  token, aggregated/distributed claims, Discovery, Federation, CIBA, and
  FAPI RFC 9068 policy. Current coverage via
  `moon coverage analyze -p mizchi/jwt -- -f summary`: `860/982`.
- [x] **JWT / OIDC offensive scenario sweep**: added attacker-oriented
  regressions for untrusted `jku` / embedded `jwk` headers, OIDC issuer
  and audience substitution, UserInfo substitution with the same `sub`,
  RFC 7523 client-assertion `jku`, JAR embedded `client_id` substitution,
  JARM mix-up (`iss` / `aud`), logout `secevent+jwt` replay, encrypted
  ID-token outer `cty` confusion and inner-issuer substitution, federation
  subject substitution, and CIBA refresh-token substitution.
- [ ] **JWT remaining coverage holes**: mostly unsupported or fixture-heavy
  algorithm branches (`RS384`/`RS512`/`ES512`/`PS384`/`PS512` sign/verify
  and JWKS mapping), malformed UTF-8 payload/header catch arms, and a few
  DPoP malformed-header claim-shape branches. Add only when backed by
  reference vectors or focused mutation fixtures.
- **PGP gpg-binary interop**: `pgp_test.mbt` sign side is currently
  tautological (sign+verify with our own code). A CI step piping our
  armor into `gpg --verify` would catch sign-side drift.
- **Cross-format fuzz breadth**: PEM → ASN.1 → PKCS#8 / PKIX integration
  fuzzing exists; extend to CMS / OCSP / CRL and JOSE containers.
- **Constant-time verification** via external profiler (`dudect` /
  `valgrind --tool=callgrind`).
- **wasm-gc + native target parity in CI**: current CI runs the default
  `wasm-gc` target only. Add `moon test --target native` and
  `--target js` matrix runs.

### Performance / footprint

- **`crypto_bigint`** real limb-based implementation (unlocks CT modexp,
  ~2-4× sign perf).
- **`asn1` encoder** streaming with length-back-patching (cuts a tree
  walk; encode is currently 2.7× decode).
- **AES-GCM GHASH** carry-less-multiplication path (not portable to
  wasm-gc without intrinsics).
- **`ed25519`** 10-limb field arithmetic (the speedup `x25519` already
  got — 14× ECDH).

### Documentation

- Update top-level `README.md` module map + perf table to reflect the
  current 35-module workspace (still listing the old 13).
- README "git commit signing" walkthrough with the three end-to-end
  flows (SSH / PGP / X.509-CMS).
- Migrate the per-module quickstart blocks into the generated
  `pkg.generated.mbti` docs once moon's doc tooling catches up.

### CI / infra

- [ ] Investigate native test runner noise:
  `warning: unhandled Platform key FamilyDisplayName`. Tests pass, but
  CI logs may become noisy or mask real native-target warnings.
- [ ] Resolve the FlakeHub auth warning emitted by
  `DeterminateSystems/nix-installer-action` (`Unable to authenticate to
  FlakeHub`). The install itself succeeds via the public mirror.
- [ ] Cache `~/.moon/registry` between CI runs so `moon update` doesn't
  re-fetch `moonbitlang/x` each time.
