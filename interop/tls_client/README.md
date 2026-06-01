# tls13 live interop harness

Drives the pure-MoonBit `tls13` **client** through a real TLS 1.3 1-RTT
handshake over a TCP socket and exchanges HTTP, proving the library
interoperates with real-world TLS stacks (OpenSSL, Cloudflare, Google, …).

The `tls13` package is socket-free by design ("the caller owns the socket").
This harness supplies that socket from Node.js and calls the MoonBit code
(compiled to JS) for every cryptographic step:

| step | who |
|---|---|
| TCP socket, TLS record framing, HTTP | `client.mjs` (Node) |
| X25519 keygen / ECDH, ClientHello, key schedule, AEAD record seal/open, **CertificateVerify + Finished** | MoonBit `tls13` / `x25519` via `interop.mbt` |

`interop.mbt` is a thin flat-typed (`Bytes`↔`Uint8Array`) shim exported to JS
via `moon.pkg.json` `link.js.exports`.

## Trust model

This is the **leaf-key + transcript** proof (`client_handshake_1rtt`): it
verifies the server holds the leaf certificate's private key and agrees on the
handshake transcript. It does **not** validate the certificate chain to a
trust anchor — that is `pkix_verify`'s job and a separate milestone.

## Run

```sh
bash interop/tls_client/run.sh
```

Spins up `openssl s_server` (TLS 1.3, X25519, self-signed P-256 leaf) and runs
the handshake for all three supported cipher suites
(AES-128-GCM, AES-256-GCM/SHA-384, ChaCha20-Poly1305). SKIPs cleanly if
`openssl` / `node` / `moon` are missing.

Optional real public-server smoke (needs outbound network):

```sh
TLS_INTEROP_REMOTE=1 bash interop/tls_client/run.sh
```

## Manual

```sh
moon build --target js
node interop/tls_client/client.mjs <host> <port> [sni] [suite_u16]
# e.g. node interop/tls_client/client.mjs cloudflare.com 443 cloudflare.com 4865
```
`suite_u16`: `4865` AES-128-GCM, `4866` AES-256-GCM, `4867` ChaCha20-Poly1305.
