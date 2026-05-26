# mizchi/hpke

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.


Hybrid Public Key Encryption (RFC 9180) for MoonBit.

v0 implements a single ciphersuite — the one shipped today by Apple iMessage
contact-key-verification, the OHTTP draft, and TLS 1.3 ECH:

| Component | Algorithm | ID |
|---|---|---|
| KEM  | DHKEM(X25519, HKDF-SHA256) | 0x0020 |
| KDF  | HKDF-SHA256                | 0x0001 |
| AEAD | ChaCha20Poly1305           | 0x0003 |

Only `Mode_Base` (sender + receiver ephemeral, no PSK, no static-static auth).

## Status

Verified byte-for-byte against the cfrg test-vector file for RFC 9180 §A.1.1
(`key`, `base_nonce`, `enc`, `exporter_secret`, three sealed ciphertexts, and
three exported values).

## Example

```moonbit skip
// Sender side. `sk_e` MUST come from a fresh CSPRNG — see `mizchi/getrandom`.
// This module deliberately does not call into an RNG so it stays target-pure
// and unit-testable.
let info : Bytes = b"example application"
let (enc, ctx_s) = @hpke.setup_base_s(pk_r, info, sk_e=ephemeral_priv)
let ct = ctx_s.seal(b"aad", b"hello")

// Receiver side. `enc` is the 32-byte ephemeral pubkey sent along with `ct`.
let ctx_r = @hpke.setup_base_r(enc, sk_r, info)
let pt = ctx_r.open(b"aad", ct)
// pt == b"hello"

// Export an application secret (e.g., for a follow-up TLS channel).
let app_secret = ctx_s.export(b"app-secret-v1", 32)
```

## What's missing (in order of next-to-add)

- **Mode_PSK** — adds `psk` + `psk_id` to the key schedule (single boolean
  branch in `key_schedule_base`)
- **Mode_Auth / Mode_AuthPSK** — adds a static sender keypair and a second DH
- **More AEADs** — AES-128-GCM and AES-256-GCM are 1-line dispatches once
  `mizchi/aead` is plumbed through
- **More KEMs** — DHKEM(P-256), DHKEM(P-521); X448 needs an X448 module first
- **`DeriveKeyPair`** — RFC 9180 §7.1.3 ikm-driven key generation. Currently
  callers pass `sk_e` directly; this is fine for tests and for callers
  generating ephemerals via `mizchi/getrandom`.
