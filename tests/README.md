# tests/

Integration / interop harnesses that exercise the library against **external,
real-world implementations** (as opposed to the in-tree `*_test.mbt` unit and
KAT tests that live inside each package).

Each harness SKIPs cleanly (exit 0) when its external tooling is absent, so the
suite stays green on minimal images, and is wired into `.github/workflows/ci.yml`.

| dir | what | external tool | CI job |
|---|---|---|---|
| `tls13_interop/` | drives the MoonBit TLS 1.3 **client** (compiled to JS) through a live 1-RTT handshake + HTTP, with certificate-chain validation, across X25519 / **P-256 / P-384** key-share groups | `openssl s_server`, `node` | `tls13-interop` |
| `tls12_interop/` | drives the MoonBit TLS 1.2 **ECDHE** crypto (compiled to JS) through a live 1-RTT handshake + HTTP against `openssl s_server -tls1_2`, across AES-128/256-GCM × ECDSA/RSA leaf × X25519/P-256/P-384 group | `openssl s_server`, `node` | `tls13-interop` |
| `jose_interop/` | MoonBit signs JWTs (EdDSA / ES256 / HS256); Node's built-in crypto verifies the JWS | `node` | `crypto-interop` |
| `aead_interop/` | MoonBit seals (ChaCha20-Poly1305 / AES-128-GCM / AES-256-GCM); Node opens + authenticates | `node` | `crypto-interop` |
| `verify_shim/` | reverse: Node signs JWTs (EdDSA/ES256/RS256/PS256/HS256) + seals AEAD; **MoonBit verifies / decrypts** and rejects tampered artifacts | `node` | `crypto-interop` |
| `pkix_interop/` | openssl mints a root→intermediate→leaf X.509 chain; **MoonBit `pkix_verify` validates** it (+ expired / missing-intermediate / wrong-name / untrusted-anchor negatives) | `openssl`, `node` | `crypto-interop` |
| `ssh_interop/` | `ssh-keygen -Y sign` (Ed25519/ECDSA/RSA) produces SSHSIG; **MoonBit `ssh` verifies** via allowed_signers (+ tampered / wrong-principal / wrong-namespace negatives) | `ssh-keygen`, `node` | `crypto-interop` |
| `pgp_interop/` | reverse of `pgp/gpg_interop.sh`: `gpg` signs (Ed25519/RSA/ECDSA-P256/P384); **MoonBit `pgp` verifies** (+ tampered negatives) | `gpg`, `node` | `crypto-interop` |
| `jwe_interop/` | JWE (`dir`, `RSA-OAEP-256` + AES-GCM) **both directions**: MoonBit `jwe` encrypt↔decrypt vs Node crypto (+ tamper) | `node` | `crypto-interop` |
| `cms_interop/` | `openssl cms -sign` detached SignedData (ECDSA/RSA); **MoonBit `cms` verifies** (+ tampered) | `openssl`, `node` | `crypto-interop` |
| `pkcs8_interop/` | `openssl genpkey` PKCS#8 (RSA/EC-P256/P384/Ed25519); **MoonBit loads + signs**, Node verifies the JWS (+ tamper) | `openssl`, `node` | `crypto-interop` |

See each subdirectory's `README.md` for details.
