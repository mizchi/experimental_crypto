# tls12_interop

Live interop for the `mizchi/experimental_crypto/tls12` module: a full TLS 1.2
**ECDHE** 1-RTT handshake against a real `openssl s_server -tls1_2`, followed by
an HTTP GET / response round trip.

Node (`client.mjs`) only does socket I/O and record/handshake framing; every
cryptographic step is the MoonBit `tls12` code compiled to JS (`interop.mbt`
exports): ClientHello build, ServerHello/Certificate/ServerKeyExchange parse,
**ServerKeyExchange signature verification against the leaf cert**, ECDHE shared
secret (X25519 / P-256 / P-384), PRF key schedule, GCM record seal/open, and the
client Finished.

### What "pass" proves

The server only emits its `ChangeCipherSpec` + **encrypted** Finished (instead
of an alert) if our derived client write keys and client Finished `verify_data`
are correct. The driver then decrypts that server Finished under the derived
server keys and exchanges application data (HTTP GET → the `-www` page). A clean
round trip therefore exercises, end to end:

- ECDHE agreement on the negotiated group (X25519 / P-256 / P-384),
- the ServerKeyExchange signature path (ECDSA-P256/P384 and RSA-PKCS#1),
- `master_secret` / `key_block` derivation and the GCM record layer in both
  directions.

### Matrix (`run.sh`)

| cipher suite | group | leaf key |
|---|---|---|
| ECDHE-ECDSA-AES128-GCM-SHA256 | X25519 | ECDSA P-256 |
| ECDHE-ECDSA-AES256-GCM-SHA384 | P-384 | ECDSA P-256 |
| ECDHE-ECDSA-AES128-GCM-SHA256 | P-256 | ECDSA P-256 |
| ECDHE-RSA-AES128-GCM-SHA256 | X25519 | RSA-2048 |
| ECDHE-RSA-AES256-GCM-SHA384 | P-256 | RSA-2048 |

### Run

```sh
bash tests/tls12_interop/run.sh
```

SKIPs cleanly (exit 0) when `openssl`, `node`, or `moon` is absent. Wired into
the `tls13-interop` CI job.
