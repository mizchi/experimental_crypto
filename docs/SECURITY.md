# Security Posture

`mizchi/experimental_crypto` has been through **three rounds of independent
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
| CVE-2022-21449 — ECDSA "Psychic Signatures" (s=0 / r=0 / r=s=0) | `p256` / `p384` / `p521` / `secp256k1` | ✓ rejected |
| CVE-2020-0601 — ECDSA Curveball (off-curve pubkey) | `p256` / `p384` / `p521` / `secp256k1` | ✓ rejected |
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

- **ECDSA sign-side scalar multiplication** for P-256, P-384, and secp256k1
  now uses fixed-iteration complete-addition field paths, and final ECDSA
  nonce inverses no longer use `@bigint.pow`. This is a measured
  constant-time candidate for the archived private-operation workload set,
  backed by Linux-native callgrind coverage, wasm-gc / wasm in-process
  dudect-style evidence, and repeated native / JS / wasm-gc / wasm timing
  evidence. It is not a constant-clock proof.
- **P-521 / ES512 signing** now routes sign-side base-point multiplication and
  final nonce inversion through fixed-limb / fixed-iteration paths. It is
  wired into the leakage harness, but it was added after the archived evidence
  run below and still needs repeated calibrated evidence before the same
  measured-candidate status.
- **RSA / JWE private modexp** routes through `crypto_bigint` fixed-limb
  modular exponentiation instead of `@bigint.pow`. This is fixed-iteration and
  branchless in source structure with direct `crypto_bigint` add/sub/mul/pow
  leakage workloads and a passing repeated evidence profile, but still does
  not provide CRT hardening, blinding, or a generated-code proof across
  allocation, GC, and microarchitectural behavior.
- **X25519 ECDH** uses a 10-limb Montgomery ladder with conditional swaps and
  now has sparse-vs-dense scalar leakage workloads across the smoke/profile
  harnesses. It is a measured candidate for the archived workload, not a
  constant-clock claim across MoonBit backends.
- **Verify-side timing**: variable-time too, but only on public inputs;
  no key material leaks.

The current archived evidence is manual `Leakage Profile` run `26587352022`
on `1ff288146603df1dc9b6b1829b3b30a3dc5a81f2`, artifact `7271878741`.
That run passed `leakage_harness/profile_evidence_gate.sh` with repeated
native / JS / wasm-gc / wasm timing rows, wasm-gc / wasm dudect rows, and
native callgrind rows for every private-operation workload that existed at
that revision. CI keeps the same classes under smoke gates; newly added
private-operation workloads such as P-521 sign / nonce-inverse must pass a new
manual evidence profile before receiving the same measured-candidate status.

### Caller responsibilities

- **JWT `kid`** is returned verbatim. If the caller uses it as a
  file-system path or URL component, they MUST sanitise it.
- **PSS sign for JWT** requires caller-supplied salt of exactly hLen bytes
  (32 / 48 / 64 for PS256 / PS384 / PS512). The JWT layer does not provide an
  RNG; callers must generate fresh salt. Verification enforces RFC 7518
  `sLen = hLen` and rejects deterministic no-salt PSx tokens.
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
