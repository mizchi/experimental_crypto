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

Three modes, selected by the host:

| env | mode | function |
|---|---|---|
| (none) | leaf key + transcript only (no chain) | `client_handshake_1rtt` |
| `TLS_ANCHOR=<pem>` | validate the chain to that single CA cert | `client_handshake_1rtt_verified` |
| `TLS_CA_BUNDLE=<pem>` | pick the anchor from a system CA bundle | `client_handshake_1rtt_verified` |

In the verified modes MoonBit's `pkix_verify` checks the leaf→anchor
signatures, validity, basicConstraints/keyUsage, and the RFC 6125 dNSName SAN
identity against the SNI hostname.

## Run

```sh
bash tests/tls13_interop/run.sh
```

Generates a test CA + leaf chain, spins up `openssl s_server` (TLS 1.3,
X25519), and runs the handshake for all three supported cipher suites
(AES-128-GCM, AES-256-GCM/SHA-384, ChaCha20-Poly1305), **validating the chain
to the test CA** (`TLS_ANCHOR`). SKIPs cleanly if `openssl` / `node` / `moon`
are missing. This is what CI runs (no outbound network).

Optional real public-server smoke (needs outbound network); validates the
chain to the system CA bundle if one is found:

```sh
TLS_INTEROP_REMOTE=1 bash tests/tls13_interop/run.sh
```

## Manual

```sh
moon build --target js
node tests/tls13_interop/client.mjs <host> <port> [sni] [suite_u16]
# e.g. node tests/tls13_interop/client.mjs cloudflare.com 443 cloudflare.com 4865
```
`suite_u16`: `4865` AES-128-GCM, `4866` AES-256-GCM, `4867` ChaCha20-Poly1305.
