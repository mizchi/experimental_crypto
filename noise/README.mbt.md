# noise

> **EXPERIMENTAL — not production-grade. Audit before use. No warranty.**

Pure-MoonBit implementation of the [Noise Protocol
Framework](https://noiseprotocol.org/noise.html) (rev 34), instantiated as
**25519 + ChaChaPoly + SHA256** — the same primitive lineup as the `age_format`
module, here driving a mutual-authentication secure channel (the basis of
WireGuard and Signal's X3DH).

## Status

- **CipherState / SymmetricState / HandshakeState** per §5, with the Noise
  HKDF (§4.3), `MixKey` / `MixHash` / `EncryptAndHash` / `Split`, and the
  ChaChaPoly nonce of §12.3.
- **Patterns**: `NN`, `NK`, `XX`, `IK`. Drive a handshake with
  `write_message` / `read_message` (peers alternate, initiator first); when
  `is_finished`, call `split` for the two transport `CipherState`s.

Verified byte-for-byte against the flynn/noise test vectors for each pattern's
`*_25519_ChaChaPoly_SHA256` instance — every handshake message and the first
transport message in each direction — plus a tampered-message rejection test.

The handshake is pure: the caller supplies the local static and ephemeral
private keys (the ephemeral MUST come from a CSPRNG, unique per handshake), and
owns the socket. Not yet implemented: PSK modifiers, rekey, fallback patterns,
and the deferred/one-way pattern families.

## Security Disclaimer ⚠️

This implementation of these cryptographic algorithms is provided without any
security endorsement or professional certification. The experimental_crypto
project should be considered:

- An educational reference implementation
- Experimental cryptography software
- Not reviewed by third-party security experts
