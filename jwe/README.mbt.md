# mizchi/jwe

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.


Minimal JWE (JSON Web Encryption, RFC 7516) implementation —
**Compact Serialization only**.

## Supported algorithms (RFC 7518)

Key management (`alg`):
- `dir` (§4.5) — direct symmetric key; caller's key is the CEK
- `A256KW` (§4.4) — AES-256 Key Wrap (RFC 3394)
- `RSA-OAEP-256` (§4.3) — RSA-OAEP with SHA-256 + MGF1-SHA-256

Content encryption (`enc`):
- `A128GCM` (§5.3) — AES-128-GCM
- `A256GCM` (§5.3) — AES-256-GCM

## Out of scope (intentional)

- ECDH-ES family (`alg` = "ECDH-ES", "ECDH-ES+A256KW", …): needs an
  ephemeral key + curve agreement, not wired in v0.
- PBES2 family (`alg` = "PBES2-HS256+A128KW", …): see `mizchi/pkcs8` for
  the underlying PBKDF2 + AES-KW primitives.
- A256CBC-HS512 / A128CBC-HS256 composite (`enc`): possible to add since
  `mizchi/aead` already exports `aes_cbc_*`, but skipped for v0.
- JWE JSON Serialization (RFC 7516 §3.2) — only the dot-separated compact
  form is implemented.
- `zip` header (DEFLATE pre-compression).

## API

```moonbit nocheck
pub fn encrypt(
  plaintext : Bytes,
  alg : JweAlg,
  enc : JweEnc,
  key : EncryptionKey,
  cek? : Bytes,           // required for dir; required in v0 for wrapped
                          // modes (no RNG yet)
  iv? : Bytes,            // required in v0
  oaep_seed? : Bytes,     // required when alg == RSA-OAEP-256
  extra_header? : Map[String, Json],
) -> String raise JweError

pub fn decrypt(token : String, key : DecryptionKey) -> Bytes raise JweError
```

## Security caveats

- AES is not constant-time (T-table). Same caveat as `mizchi/aead`.
- RSA-OAEP public encrypt uses `@bigint.pow` only over public inputs.
- RSA-OAEP private unwrap uses `crypto_bigint` fixed-limb exponentiation, but
  still needs external leakage measurement before claiming full constant-time
  behavior.
- RSA-OAEP unwrap is **Manger-attack-resistant in error shape**: every
  validation failure (size, Y != 0x00, lHash mismatch, missing 0x01
  separator) collapses into a single `AuthenticationFailed`. This blocks
  the textbook padding oracle (RFC 8017 §7.1.2 step 3.g), but it is not a
  standalone constant-time proof.
- No RNG path in v0: the caller MUST pass `cek`, `iv`, and `oaep_seed`
  explicitly. This is deliberate (deterministic tests, no hidden
  side-effect), not a permanent design.
