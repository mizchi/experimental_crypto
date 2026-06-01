# ssh interop (SSHSIG)

**OpenSSH `ssh-keygen -Y sign` produces SSHSIG signatures; MoonBit `ssh`
verifies them** — the equivalent of `ssh-keygen -Y verify -f allowed_signers`.

- `interop.mbt` is a JS-export shim: `ssh_verify(allowed_signers, principal,
  armor, message_hex, namespace)` returning 1/0 via
  `ssh.verify_with_allowed_signers`.
- `driver.mjs` (Node) generates **Ed25519, ECDSA-P256, and RSA-2048** keys with
  `ssh-keygen`, signs a message (`-Y sign -n git`), and builds an
  `allowed_signers` line. A real `ssh-keygen -Y verify` sanity-checks each
  fixture, then MoonBit is asserted to:
  - accept the valid signature, and
  - reject a tampered message, a wrong principal, and a wrong namespace.

```sh
bash tests/ssh_interop/run.sh
```
