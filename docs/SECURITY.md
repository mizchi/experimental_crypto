# Security Posture

`mizchi/moonbit-crypto` has been through **three rounds of independent
code review** plus a focused PKCS#8 / sign-side audit. This document
records the findings, the fixes, and the residual caveats so readers can
audit the audit.

## Audit history

| Round | Scope | Findings | Status |
|---|---|---|---|
| 1 | Sign side + PEM loaders (commits `bdc3194..1461cda`) | 1 structural bug + 7 mitigation gaps | All addressed in `20b1b94` |
| 2 | Full repo modules untouched by round 1 | 2 real bugs + 24 mitigation gaps | Round-2 fixes in `ee0654b` + `861d87a` |
| 3 | Remaining T1 / T2 expansion | (in-progress: same suite re-audits as items land) | See [TODO.md](../TODO.md) |

### Round 1 findings (closed)

- **BUG**: `from_pkcs8_der` on `@p256` / `@p384` accepted **any
  `id-ecPublicKey` blob** without verifying the named-curve OID. A P-384
  PKCS#8 with a scalar fitting in 32 bytes would silently load as P-256.
  Fixed: outer `info.algorithm.parameters` is checked; inner SEC1
  `parameters [0]` cross-checked.
- PGP MPI trailing-bytes accepted (malleability) → strict consumption.
- RSA `n_bytes_len` mis-cached on non-canonical INTEGER → use parsed
  BigInt's natural byte length.
- JWT RS256 sign aborted on too-small modulus → typed error.
- ECDSA / RSA sign timing caveat → doc-commented on each
  `PrivateKey::sign`.

### Round 2 findings (closed)

- **BUG**: CMS `id-rsaEncryption` hash dispatch hard-coded SHA-256,
  silently failing legit SHA-384/512 signatures. Now uses
  `digestAlgorithm` and cross-checks with the signature OID.
- **BUG**: pkix_verify `nameConstraints` replaced the parent's set
  instead of intersecting (RFC 5280 §6.1.4(g)). A sub-CA could widen
  its parent's constraints. Now intersects permitted, unions excluded.
- **BUG**: git_object's "last header line" off-by-one let a second
  `gpgsig` header slip through into the signed body. Fixed:
  `byte_index <= header_end` + explicit multi-gpgsig rejection.
- `asn1.ObjectIdentifier::from_arcs` validation (aliasing across
  `[5,10]` vs `[2,130]`).
- JWT `crit` (RFC 7515 §4.1.11) and `b64` (RFC 7797) headers now
  rejected.

### Round 2 round-3 leftovers (closed)

- CMS `SignerInfo.sid` now parsed: `IssuerAndSerialNumber` matched
  against the embedded certs by byte-comparing the encoded Name plus
  sign-byte-normalised serial.
- asn1 encoder gained MAX_DEPTH=32 (matching the decoder) to defend
  against caller-constructed deeply-nested `Element` values.
- nameConstraints non-DNS GeneralName forms (IP / RFC822 / DN / …) now
  fail-closed with `MalformedExtension` per RFC 5280 §4.2.1.10.
- pathLenConstraint regression tests cover pathLen=0 with extra
  intermediate (reject) and pathLen=1 with 1 intermediate (accept).

## Attack-style test coverage

The test suite includes CVE-class attack tests that assert the
implementation **rejects** the exploit:

| CVE / attack | Module | Status |
|---|---|---|
| CVE-2015-9235 — JWT `alg:none` | `jwt` | ✓ rejected |
| CVE-2016-10555 — JWT alg confusion (HS256 token + RS256 key) | `jwt` | ✓ rejected |
| CVE-2022-21449 — ECDSA "Psychic Signatures" (s=0 / r=0 / r=s=0) | `p256` / `p384` / `secp256k1` | ✓ rejected |
| CVE-2020-0601 — ECDSA Curveball (off-curve pubkey) | `p256` / `p384` / `secp256k1` | ✓ rejected |
| CVE-2006-4339 / CVE-2014-1568 — RSA Bleichenbacher / BERserk (PKCS#1 v1.5 trailing garbage) | `rsa` | ✓ rejected |
| CVE-2018-0739 — ASN.1 deep-nesting DoS | `asn1` | ✓ MAX_DEPTH on both decoder + encoder |
| RFC 7748 §6.1 — X25519 small-subgroup pubkey | `x25519` | ✓ AllZeroSharedSecret raised |
| Ed25519 signature malleability (S ≥ L) | `ed25519` | ✓ `verify_strict` rejects |
| RFC 5280 §4.2 — unknown critical extension | `pkix_verify` | ✓ `UnknownCriticalExtension` |
| RFC 5280 §6.1.4(n) — issuer keyUsage missing keyCertSign | `pkix_verify` | ✓ `KeyUsageMissingCertSign` |
| RFC 5280 §4.2.1.10 — nameConstraints DNS subtree | `pkix_verify` | ✓ excluded blocks SAN |
| ASN.1 non-canonical INTEGER (`02 02 00 01`) | `asn1` | ✓ rejected |

## Documented caveats

The following items are not exploitable in the deployed API but are
worth noting:

### Side channels (sign-side only)

- **ECDSA `scalar_mult`** (p256/p384/secp256k1) walks the bit pattern
  of the secret nonce `k` via variable-time double-and-add. RFC 6979
  produces a deterministic `k` from (privkey, message) so the **value**
  of `k` is fixed for a given message, but the **execution time** of
  scalar_mult leaks `k`'s bit pattern. Each `PrivateKey::sign` doc
  comment marks this.
- **RSA `BigInt.pow`** is variable-time on `d`. We do **not** do CRT,
  so no CRT-fault-injection vector either, but a timing attacker who
  triggers many sign operations may recover `d`.
- **Verify-side timing**: variable-time too, but only on public inputs;
  no key material leaks.

Closing these requires a constant-time scalar-mult ladder and a
constant-time modular exponentiation, both of which need
`crypto_bigint` rewritten as a real limb-based implementation.

### Caller responsibilities

- **JWT `kid`** is returned verbatim. If the caller uses it as a
  file-system path or URL component, they MUST sanitise it.
- **PSS sign for JWT** uses deterministic PSS (sLen=0) since no vetted
  RNG is exposed at the JWT layer. This deviates from RFC 7518 §3.5
  (which mandates sLen=hLen) and is documented in the jwt.mbt module
  comment. Callers needing RFC 7518 interop call `@rsa.sign_pss`
  directly with a freshly-sampled salt.
- **OCSP / CRL revocation** is parsed and verified but NOT consulted by
  `pkix_verify.verify_chain` automatically — callers must wire them.

### Partial enforcement

- **`pkix_verify` nameConstraints**: DNS subtree subset only. Non-DNS
  GeneralName forms (IP, RFC822, URI, DN, …) cause the chain to be
  rejected; partial-IP enforcement is not implemented.
- **`pkix_verify` certificatePolicies / policyConstraints /
  inhibitAnyPolicy**: recognised as critical extensions but the
  policy-graph processing of RFC 5280 §6.1.4(a)..(o) is out of scope.
- **`pkix_verify` DN linkage** is byte-compare on the encoded Name. No
  LDAPv3 string-prep, so two valid certs with `CN=example.com` vs
  `CN=Example.com` will fail to link (refuses valid chains rather than
  accepting wrong ones — safe but restrictive).

## Verifying the audit yourself

```bash
# Run the full test suite
moon test

# Run only the attack-style tests
moon test --filter ATTACK

# Inspect the audit-fix commits
git log --grep '^fix' --oneline -- '**/*.mbt'
```

The three round-of-fix commits to read are `20b1b94`, `ee0654b`,
`861d87a`. The TODO.md sweep commit (`d3f8d7b`) closed the secp256k1 /
RSA-PSS / PBES2 algorithm gaps. The T1+T2 sweep commit (`f66b7a1`)
closed JWE, COSE/CBOR, BIP-32, OCSP/CRL, PGP v6, and the gpgsm chain
test.
