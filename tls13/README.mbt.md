# tls13

> **EXPERIMENTAL — not production-grade. Audit before use. No warranty.**

Pure-MoonBit building blocks for a TLS 1.3 (RFC 8446) client. This module does
**not** perform socket I/O; like the rest of the workspace it works over byte
buffers and leaves transport to the caller.

## Status

Implemented:

- **Key schedule** (RFC 8446 §7.1): `HKDF-Extract`, `HKDF-Expand`,
  `HKDF-Expand-Label`, `Derive-Secret`, and the full secret chain — Early,
  Handshake, and Master secrets; client/server handshake and application traffic
  secrets; exporter/resumption master secrets; per-record write key/IV; and the
  Finished key. SHA-256 and SHA-384 suites.

- **Record layer** (RFC 8446 §5): `seal_record` / `open_record` for
  TLSCiphertext framing — TLSInnerPlaintext (content || ContentType || zero
  padding), the per-record nonce (sequence number XORed with the write IV), and
  the record header as AEAD additional data. Cipher suites
  `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`.

- **Handshake framing + authentication** (RFC 8446 §4): `handshake_message` /
  `parse_handshake` / `parse_handshake_flight` for the `msg_type || uint24 len ||
  body` framing; the Finished MAC (`finished_mac`, `build_finished`, and a
  constant-time `verify_finished`); and the CertificateVerify signed-content
  builder (`certificate_verify_content` + the server/client context strings).

- **Server-flight parsers** (`messages.mbt`): `parse_server_hello` (selected
  cipher suite, `key_share`, `supported_versions`, HelloRetryRequest
  detection), `parse_certificate` (the certificate chain as DER blobs), and
  `parse_certificate_verify` (signature scheme + signature), over a fail-closed
  byte reader that rejects truncation, length mismatches, and trailing data.

All layers are verified against the RFC 8448 §3 "Simple 1-RTT Handshake" trace,
including an end-to-end check that reconstructs the transcript and confirms the
server Finished MAC, and the byte-exact ServerHello / Certificate /
CertificateVerify fields.

Not yet implemented (planned): the ClientHello builder, the SignatureScheme →
`rsa`/`p256`/`ed25519` dispatch that verifies CertificateVerify against the leaf
certificate's key, and the client state machine (wiring `pkix_verify` for
chain verification).

## Example

```moonbit nocheck
///|
test {
  let h = @tls13.Hash::Sha256
  let early = h.early_secret(b"") // no PSK
  let handshake = h.handshake_secret(early, ecdhe_shared_secret)
  let s_hs = h.server_handshake_traffic_secret(handshake, transcript_ch_sh)
  let key = h.write_key(s_hs, 16) // AES-128 key
  let iv = h.write_iv(s_hs)
  ignore(key)
  ignore(iv)
}
```
