# tests/

Integration / interop harnesses that exercise the library against **external,
real-world implementations** (as opposed to the in-tree `*_test.mbt` unit and
KAT tests that live inside each package).

Each harness SKIPs cleanly (exit 0) when its external tooling is absent, so the
suite stays green on minimal images, and is wired into `.github/workflows/ci.yml`.

| dir | what | external tool | CI job |
|---|---|---|---|
| `tls13_interop/` | drives the MoonBit TLS 1.3 **client** (compiled to JS) through a live 1-RTT handshake + HTTP, with certificate-chain validation | `openssl s_server`, `node` | `tls13-interop` |
| `jose_interop/` | MoonBit signs JWTs (EdDSA / ES256 / HS256); Node's built-in crypto verifies the JWS | `node` | `crypto-interop` |
| `aead_interop/` | MoonBit seals (ChaCha20-Poly1305 / AES-128-GCM / AES-256-GCM); Node opens + authenticates | `node` | `crypto-interop` |

See each subdirectory's `README.md` for details.
