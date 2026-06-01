# cms interop (CMS / PKCS#7 SignedData)

**openssl `cms -sign` produces a detached SignedData; MoonBit `cms` parses and
verifies it** against the message, using the embedded signer certificate.

- `interop.mbt` JS-export shim: `cms_verify(sd_der_hex, message_hex)` →
  1 valid / 0 invalid / 2 parse error (`cms.parse_signed_data` +
  `cms.verify_detached`).
- `driver.mjs` signs a message with `openssl cms -sign -binary` for an
  **ECDSA P-256** and an **RSA-2048** signer, then asserts MoonBit accepts the
  valid signature and rejects a tampered message.

```sh
bash tests/cms_interop/run.sh
```
