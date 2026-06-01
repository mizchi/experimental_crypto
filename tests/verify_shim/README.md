# verify-shim interop (reverse direction)

The complement to `jose_interop` / `aead_interop`: here **Node produces and
MoonBit verifies / decrypts**, proving the library accepts real-world artifacts
and rejects tampered ones.

- `interop.mbt` is a JS-export shim exposing `jwt_verify(token, jwk, secretHex)`
  (returns 1/0) and `aead_open(algId, key, nonce, aad, ct)` (returns plaintext
  hex or `"ERR"`).
- `driver.mjs` (Node) generates keys with `crypto.generateKeyPairSync`, signs
  JWTs (**EdDSA, ES256, RS256, PS256, HS256**) and seals AEAD ciphertexts
  (**ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM**), then asserts MoonBit:
  - accepts each valid signature / ciphertext, and
  - rejects a tampered signature / forged tag.

Exercises `jwt.verify`, `jwk.parse_public`, the verify-side signature
primitives, RSA-PSS/PKCS1, and `aead.open` against an independent producer.

```sh
bash tests/verify_shim/run.sh
```
