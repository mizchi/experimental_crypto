# jose interop

MoonBit signs JWTs; **Node's built-in `crypto` verifies them** (no npm).

- `main.mbt` (`moon run`) signs a JWT with EdDSA (Ed25519), ES256 (P-256), and
  HS256, and prints each token together with the public key as a JWK
  (`jwk.serialise_public`) or the shared secret.
- `verify.mjs` imports the JWK via `crypto.createPublicKey({format:'jwk'})` and
  verifies the JWS signature over `header.payload` (ES256 as raw r‖s /
  IEEE-P1363, EdDSA via Ed25519, HS256 by recomputing the HMAC).

Exercises `jwt.sign`, the `p256` / `ed25519` signing primitives, and
`jwk.serialise_public` against an independent JOSE-capable verifier.

```sh
bash tests/jose_interop/run.sh
```
