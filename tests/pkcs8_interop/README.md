# pkcs8 interop (key loading)

**openssl generates a PKCS#8 private key; MoonBit loads it via `from_pkcs8_pem`,
signs a JWT, and Node verifies the JWS** with the public key derived from the
same PEM — proving MoonBit decoded openssl's PKCS#8 key material correctly.

- `interop.mbt` JS-export shim: `pkcs8_sign_jws(alg, pkcs8_pem)` loads the key
  (`rsa` / `p256` / `p384` / `ed25519` `from_pkcs8_pem`) and signs a fixed JWT.
- `driver.mjs` runs `openssl genpkey` for **RS256, ES256, ES384, EdDSA**, then
  asserts the JWS verifies in Node and that a tampered signature is rejected.

```sh
bash tests/pkcs8_interop/run.sh
```
