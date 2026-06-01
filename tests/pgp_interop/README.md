# pgp interop (reverse: gpg signs → MoonBit verifies)

Complements `pgp/gpg_interop.sh` (forward: MoonBit signs → gpg verifies). Here
**real GnuPG produces detached signatures and MoonBit `pgp.verify_armor`
verifies them**.

- `interop.mbt` is a JS-export shim: `pgp_verify(pubkey_armor, message_hex,
  sig_armor)` → 1 valid / 0 invalid / 2 key parse error
  (`pgp.parse_pubkey_armor` + `pgp.verify_armor`).
- `driver.mjs` (Node) drives `gpg` to generate **Ed25519, RSA-2048, ECDSA
  nistp256, and ECDSA nistp384** keys, export the public key, and detach-sign a
  message, then asserts MoonBit:
  - accepts the valid signature, and
  - rejects a tampered message and a tampered signature.

```sh
bash tests/pgp_interop/run.sh
```
