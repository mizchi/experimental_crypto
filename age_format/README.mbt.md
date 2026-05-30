# age_format

> **EXPERIMENTAL — not production-grade. Audit before use. No warranty.**

Pure-MoonBit implementation of the [age](https://age-encryption.org/v1) v1 file
encryption format, for X25519 recipients. Composes `mizchi/x25519` (ECDH),
`mizchi/hkdf` (HKDF-SHA256), `mizchi/aead` (ChaCha20-Poly1305), and
`mizchi/hash` (HMAC-SHA256), plus a small Bech32 decoder for age key strings.

## Status

- **Decryption** (`decrypt`): parses the textual header, unwraps the file key
  from an `X25519` stanza, verifies the header HMAC, and decrypts the STREAM
  payload (64 KiB ChaCha20-Poly1305 chunks). Verified against the C2SP/CCTV age
  test vectors (X25519 success / no-match / HMAC-failure / header-failure /
  payload-failure cases), with the same failure classification.
- **Encryption** (`encrypt_x25519`): a deterministic core that takes the file
  key, ephemeral scalar, and payload nonce explicitly (the caller supplies the
  randomness from a CSPRNG). Round-trips with `decrypt` across single-chunk,
  multi-chunk, and empty payloads.
- **Keys**: `X25519Identity::from_bech32` parses `AGE-SECRET-KEY-1…`;
  `public_key_bytes` yields the matching recipient public key.

Not implemented (planned): the `scrypt` (passphrase) recipient, ASCII armor,
and a CSPRNG-wrapping `encrypt` convenience.
