# moonbit-crypto

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

Pure MoonBit building blocks for crypto and PKI. A `moon.work` workspace of
35 self-contained modules, each one focused on a single RFC-level concern.
The implementations stay on top of `moonbitlang/core` and the small
`moonbitlang/x/crypto` extension; nothing else.

The constant-time properties of the field arithmetic are not yet up to
the bar of `dalek` or `RustCrypto`; the file headers call out exactly
where the gaps are.

## Module map

| Module        | Spec                                         | Tests | Notes                                                          |
| ------------- | -------------------------------------------- | ----- | -------------------------------------------------------------- |
| `asn1`        | X.690 (DER), X.680                           | 54    | Tag, length, OID, primitives, SEQUENCE, SET, BIT STRING, time  |
| `pem`         | RFC 7468                                     | 12    | Multi-block, lax input, strict 64-char output                  |
| `pkix`        | RFC 5280                                     | 15    | X.509 v3 cert, Let's Encrypt R10 roundtrip                     |
| `pkcs8`       | RFC 5208 / 5958                              | 13    | PrivateKeyInfo, EncryptedPrivateKeyInfo, RustCrypto fixtures   |
| `hkdf`        | RFC 5869                                     | 6     | HKDF-SHA-256; SHA-384/512 deferred until x/crypto exposes them |
| `pbkdf2`      | RFC 8018                                     | 7     | PBKDF2-HMAC-SHA256                                             |
| `scrypt`      | RFC 7914                                     | 14    | Salsa20/8 + BlockMix + ROMix; PHC string encode / verify       |
| `argon2`      | RFC 9106                                     | 22    | Argon2d / i / id; BLAKE2b self-impl; PHC string encode / verify |
| `aead`        | RFC 8439, NIST SP 800-38D                    | 60    | ChaCha20-Poly1305 (5-limb), AES-128/256-GCM (self-impl)        |
| `x25519`      | RFC 7748                                     | 31    | 10-limb radix-2^25.5 Montgomery ladder; ~90 µs / ECDH          |
| `ed25519`     | RFC 8032                                     | 17    | SHA-512 self-impl; @bigint-backed Edwards curve (limb rewrite pending) |
| `crypto_bigint` | (Rust crypto-bigint shape)                 | 19    | Uint, Montgomery; arithmetic delegated to @bigint for now      |
| `getrandom`   | OS CSPRNG bridge                             | 6     | `crypto.getRandomValues` on JS, `arc4random_buf` / `getrandom(2)` / `BCryptGenRandom` on native |

`moon test` from the workspace root runs the full suite (270+ tests).

## Cross-implementation interop

The test suites include vectors borrowed from other implementations so the
parsers and codecs aren't only validated against bytes we produced ourselves:

- `pkix` parses the live Let's Encrypt R10 intermediate CA (PEM embedded in
  `pkix/fixtures_test.mbt`) and round-trips it byte-stable.
- `pkcs8` parses the Ed25519 PKCS#8 v1 + v2 PEM fixtures from
  `RustCrypto/formats`, including the v2 "Curdle Chairs" attribute from
  RFC 8410 §10.3.
- `aead` and `x25519` consume a subset of Project Wycheproof vectors
  covering invalid tags, modified ciphertexts, zero shared secrets,
  non-canonical public keys, etc.

## Build

```
moon test                       # all 13 modules
moon test --target all          # wasm-gc + wasm + native
moon test -p mizchi/asn1        # single module
moon bench --release -p mizchi/x25519
moon check --target all
```

The native backend uses a small C stub (`getrandom/getrandom_native.c`) that
selects `arc4random_buf` on macOS / *BSD, `getrandom(2)` on Linux, and
`BCryptGenRandom` on Windows.

## Performance baselines

Run on wasm-gc, release mode, on the author's machine. Reproduce with
`moon bench --release -p mizchi/<module>`:

| Operation                              | Time      | Notes |
| -------------------------------------- | --------- | ----- |
| asn1 encode flat SEQUENCE x100         | ~5.8 µs   | encode is 2.7× slower than decode (Encoder double-pass) |
| asn1 decode flat SEQUENCE x100         | ~2.1 µs   | |
| asn1 OID from_string                   | ~75 ns    | |
| aead ChaCha20-Poly1305 seal 1 KiB      | ~9.9 µs   | ~100 MiB/s after the 5-limb Poly1305 rewrite |
| aead ChaCha20-Poly1305 seal 16 KiB     | ~147 µs   | |
| aead ChaCha20-Poly1305 open 1 KiB      | ~8.5 µs   | |
| x25519 ECDH                            | ~92 µs    | down from 1.33 ms once we left @bigint behind |
| x25519 derive public key               | ~96 µs    | |
| pbkdf2-HMAC-SHA256 c=1k dkLen=32       | ~1.4 ms   | |
| pbkdf2-HMAC-SHA256 c=10k dkLen=32      | ~12.5 ms  | |

For comparison, `dalek` / `RustCrypto` numbers are roughly an order of
magnitude faster than what's here today. The path to closing that gap is
documented per-module in the file headers (mostly: avoid per-op
`FixedArray::make` allocations, move to 5-limb radix-2^51 once MoonBit
exposes a 64×64 → 128 multiply primitive, and add SIMD on the native
backend where possible).

## Known limitations

These are intentional and called out in the source where they apply:

- **Not constant-time end-to-end.** `crypto_bigint` and `ed25519` still
  delegate to `@bigint`, which is variable-time. `x25519` and `aead`
  (Poly1305) use limb arithmetic with branch-free conditional swaps, but
  u64 mul on wasm/JS is not formally constant-time either.
- **No XChaCha20-Poly1305 yet** (the enum variant raises
  `UnsupportedAlgorithm`).
- **No SHA-1 / SHA-384 / SHA-512 HMAC paths** in `hkdf` / `pbkdf2` until
  `moonbitlang/x/crypto` ships the corresponding hashers (the enums keep
  the variants so adding them is a one-line `match` arm).
- **No OCSP / CRL validation** in `pkix`.
- **No certificate chain verification.** `pkix` is a parser, not a verifier.
- **No GHASH carryless-multiplication intrinsic.** The `gcm` module does
  GF(2^128) bit-by-bit, which is correct but slow.

## License

Apache-2.0. Each module ships its own `LICENSE` file because `moon new`
generates one per module; the workspace inherits.

## Layout

```
.
├── moon.work                # workspace manifest, lists members
├── README.md                # this file
├── .gitignore
└── <module>/
    ├── moon.mod             # module name, version, deps
    ├── moon.pkg             # package-level imports, native stubs, target maps
    ├── <module>.mbt         # main source
    ├── <module>_test.mbt    # blackbox tests
    ├── <module>_wbtest.mbt  # whitebox tests (where useful)
    ├── pkg.generated.mbti   # public API snapshot, regenerated by `moon info`
    └── LICENSE              # Apache-2.0
```

Workspace member dependencies are declared twice: once in the dependent
module's `moon.mod` (`import { "mizchi/<dep>@0.1.0" }`) for version
resolution, and once in `moon.pkg` (`import { "mizchi/<dep>" }`) for the
package itself. The workspace resolves the version constraint to the
local path because `moon.work` lists the dep as a member, even though
the registry has no `mizchi/*` published.
