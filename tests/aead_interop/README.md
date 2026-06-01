# aead interop

MoonBit seals; **Node's built-in `crypto` opens + authenticates** (no npm).

- `main.mbt` (`moon run`) seals a known (key, nonce, aad, plaintext) under
  ChaCha20-Poly1305, AES-128-GCM, and AES-256-GCM and prints the inputs +
  ciphertext (ct‖tag) as hex.
- `verify.mjs` opens each with `crypto.createDecipheriv`, sets the AAD + auth
  tag, and checks the recovered plaintext, proving the MoonBit `aead` sealing
  matches a reference stack byte-for-byte (and that the tag authenticates).

```sh
bash tests/aead_interop/run.sh
```
