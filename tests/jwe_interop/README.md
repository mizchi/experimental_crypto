# jwe interop (RFC 7516, both directions)

MoonBit `jwe` ↔ Node's built-in crypto (RSA-OAEP-256 + AES-GCM, no npm).

- `interop.mbt` JS-export shim:
  - `jwe_encrypt_dir` / `jwe_encrypt_rsa` — MoonBit encrypts, Node decrypts.
  - `jwe_decrypt_dir` / `jwe_decrypt_rsa` — Node encrypts, MoonBit decrypts (→ "ERR" on auth failure).
- `driver.mjs` exercises **dir** (A128GCM, A256GCM) and **RSA-OAEP-256**
  (A256GCM) in both directions, plus a tamper-rejection case each. The
  RSA-OAEP path builds the public key from Node's JWK `n`/`e` (encrypt) and
  loads a PKCS#8 PEM private key (decrypt).

```sh
bash tests/jwe_interop/run.sh
```
