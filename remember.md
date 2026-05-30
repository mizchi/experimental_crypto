# remember.md — session handoff for moonbit-crypto

Working notes so another agent (or a future session) can resume cleanly.
This file is scratch/handoff documentation, not part of the library. Keep it
updated as work progresses; it can be deleted before a final squash if desired.

## TL;DR of where things stand

- Branch: `claude/module-verification-security-Q8zdI`.
- PR #2 (`fix(pkix_verify): reject empty permitted name space in nameConstraints`,
  which grew to include all the WebAuthn/asn1/EKU work below) was **merged**
  into `main` at merge commit `bcb3af4`.
- After the merge, one extra doc commit (`399e651`) sits on the branch, **1
  ahead of `main`** (not yet merged): it just corrects a stale CLAUDE.md TODO.
- Next planned feature: **EIP-712 / EIP-191** (Ethereum structured signing),
  to be developed and shipped as its own PR. Detailed plan below.

## What was done this session (all merged via PR #2 unless noted)

In chronological order on the branch:

1. `harden(webauthn)` (`7a0a0f1`) — enforce relying-party policy in the
   WebAuthn verifier: `rp_id_hash` binding, User-Present (UP), User-Verified
   (UV) via `require_user_verification~`. Added `RpIdMismatch` /
   `UserNotPresent` / `UserNotVerified` errors and an `AttestationType` enum
   (`NoAttestation` / `SelfAttestation` / `CertificateAttestation`); `none`
   attestation with an x5c is rejected. `verify_assertion` /
   `verify_attestation` now take `rp_id_hash~` + `require_user_verification~`.
2. `test(webauthn)` (`eea5aa5`) — 14-test fail-closed robustness suite
   (`webauthn/robustness_test.mbt`): malformed authenticatorData / COSE keys /
   attestation objects / clientDataJSON all rejected.
3. `feat(webauthn)` (`f594e3a`) — RS256/384/512 (RSA PKCS#1 v1.5) credential
   public keys. Added `RsaPublicKey::from_components(n, e)` to the `rsa` module
   (build from raw big-endian COSE/JWK bytes via `BigInt::from_octets`, with
   `validate_rsa_public_params`). COSE `kty=3` parsing (n@-1, e@-2, RFC 8230).
4. `feat(webauthn)` (`b572cf7`) — PS256/384/512 (RSASSA-PSS) credential keys
   via `rsa.verify_pss` (salt length = digest length). Vector generated with
   openssl (PSS saltlen=digest), pre-verified with `openssl dgst -verify`.
5. `perf(asn1)` (`d74a9df`) — single-pass DER encoder. Replaced the
   placeholder + `finish()` whole-buffer rewrite with an O(n) **size tree**
   (`element_size_tree` / `write_sized` / `tag_encoded_size` / `EncSize`).
   Byte-identical output (94 asn1 tests pass). Bench (wasm-gc release): encode
   flat 18.9→10.7us (2.4x→1.4x decode), nested 7.0→5.3us (1.5x→1.1x). The
   placeholder/patch helpers were KEPT (whitebox-tested, used by the SET-item
   child-encoder path).
6. `fix(pkix_verify)` (`619d48e`) — EKU **nesting**. `required_eku` was only
   checked on the leaf; a sub-CA whose EKU excluded the purpose could still
   issue a leaf trusted for it (false positive). Now each intermediate with an
   EKU extension must permit the requested purpose (reuses
   `enforce_required_eku` per intermediate). `verify_chain` (required_eku=None)
   unaffected, so x509-limbo / BetterTLS corpora unchanged.
7. `docs(CLAUDE)` (`399e651`, **branch-only, not on main**) — marked the aead
   XChaCha20-Poly1305 TODO resolved (it was already fully implemented +
   tested; see "stale TODOs" below).

Final test counts at end of session: full workspace **1442** (wasm-gc) all
pass; js full **1467**; native rsa/webauthn green. CI on `619d48e` was green
on all 6 jobs before merge.

## Stale TODOs discovered (already implemented; corrected the notes)

Two CLAUDE.md "既知の TODO" items turned out to be already done — the notes
predated the implementations. Verify before "implementing" anything from that
list:

- **asn1 `Encoder::write_element` double-pass** — the encoder was already
  single-pass (patch scheme); this session further removed the `finish()`
  copy. Resolved.
- **aead `XChaCha20Poly1305`** — already fully implemented: `hchacha20`
  (`aead/chacha20.mbt`), `xchacha20_poly1305_seal/open` (`aead/aead.mbt`),
  `Algorithm::XChaCha20Poly1305`, with draft-irtf-cfrg-xchacha §A.1 (HChaCha20
  KAT) + §A.3 (AEAD) vectors and fuzz round-trip tests. aead = 88/88.

## NEXT TASK: EIP-712 / EIP-191 (new module, ship as its own PR)

Goal: a verify-side (and digest-producing) Ethereum structured-signing module,
consistent with the rest of the workspace (strict parsers, fail-closed, vectors
from the spec). Likely module name: `eip712` (or `eth_sig`).

### Prerequisites to confirm first
- **keccak256**: Ethereum uses **Keccak-256**, NOT SHA3-256. They differ only
  in the domain-separation/padding byte: Keccak pads with `0x01 … 0x80`,
  SHA3 with `0x06 … 0x80`. If the workspace has SHA3 but not Keccak, add a
  Keccak-256 (parameterize the pad byte, or a dedicated impl). Check `hash/`
  and grep `keccak`/`sha3`. (As of this writing: confirm via
  `grep -rliE 'keccak|sha3' --include=*.mbt`.)
- **secp256k1**: sign/verify exist. EIP signatures are **recoverable**
  (v, r, s) and the signer is identified by Ethereum address =
  `keccak256(uncompressed_pubkey[1:])[12:]` (last 20 bytes). Check whether
  `secp256k1` exposes public-key **recovery** from (r, s, recovery_id). If
  not, either (a) implement ecrecover, or (b) scope v1 to "verify a signature
  against a supplied/known public key + derive its address" and document
  ecrecover as future. Verify-first is fine for this repo.

### EIP-191 (simpler — do first)
- `personal_sign` (version byte `0x45` = 'E'):
  `digest = keccak256("\x19Ethereum Signed Message:\n" ++ ascii(len(message)) ++ message)`.
- General EIP-191 framing: `0x19 ++ version ++ version_specific_data ++ data`.
  - `0x00`: data-with-intended-validator (`0x19 0x00 ++ validator_addr ++ data`).
  - `0x01`: structured data → this is the EIP-712 prefix (see below).
  - `0x45` ('E'): the `personal_sign` string form above.
- API: `eip191_personal_sign_hash(message: Bytes) -> Bytes` (32-byte digest);
  optionally a verify that takes a signature + expected address.

### EIP-712 (typed structured data)
- Final digest: `keccak256(0x19 ++ 0x01 ++ domainSeparator ++ hashStruct(message))`.
- `domainSeparator = hashStruct("EIP712Domain", domain)`.
- `hashStruct(s) = keccak256(typeHash(s) ++ encodeData(s))`.
- `typeHash = keccak256(encodeType)` where `encodeType` is the canonical type
  string: `MainType(field1Type field1Name,…)` followed by every referenced
  custom type sorted alphabetically, concatenated. Get this exactly right —
  it's the classic source of bugs.
- `encodeData`: each field encoded to 32 bytes:
  - atomic (`uint*`, `int*`, `bool`, `address`, `bytesN`): left/right padded
    per ABI rules (uint/int/bool/address are 32-byte left-padded big-endian;
    `bytesN` right-padded).
  - dynamic (`string`, `bytes`): `keccak256(value)`.
  - struct: `hashStruct(field)` (recursive).
  - array: `keccak256(concat(encodeData of each element))`.
- Recommended v1 scope: accept the typed-data as already-parsed MoonBit
  structures (don't parse arbitrary JSON typed-data first) OR parse the
  canonical JSON form. Given the repo uses `moonbitlang/core/json`, parsing
  the standard EIP-712 JSON (`{types, primaryType, domain, message}`) is
  feasible but fiddly; a typed builder API may be cleaner for v1 and lower
  false-positive risk. Decide based on how the test vectors are shaped.

### Test vectors (verifiable, no python needed)
- **EIP-712 canonical "Mail" example** (from the EIP-712 spec): domain
  `{name:"Ether Mail", version:"1", chainId:1, verifyingContract:0xCcCC…cCC}`,
  a `Mail` with `Person from/to` and `string contents:"Hello, Bob!"`. Known
  results: `domainSeparator = 0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f`,
  `hashStruct(message) = 0xc52c0ee5d84264471806290a3f2c4cecfe5ac5b0a1c5a2e2e2e…` (look up
  the exact value), final signing hash
  `0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2`,
  signed by privkey `0xcow…` (the spec's
  `0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d`)
  giving a specific (v,r,s) and signer address
  `0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826`. **Pull the exact hex from the
  EIP-712 spec / a trusted reference and pin them** (don't trust these from
  memory — verify each).
- **EIP-191 personal_sign**: e.g. message "hello" → known digest; or reuse
  ethers.js/viem documented vectors.
- openssl does NOT do keccak/secp256k1-recover, so cross-check against pinned
  spec/library vectors rather than generating.

### Suggested file layout
- `eip712/moon.mod`, `eip712/moon.pkg` (deps: `secp256k1`, a keccak source,
  `moonbitlang/core/json` if parsing JSON).
- `eip712/keccak256.mbt` (if not available elsewhere).
- `eip712/eip191.mbt`, `eip712/eip712.mbt`.
- `eip712/eip712_test.mbt` with the pinned spec vectors.
- Update root `README.md` module map + remove EIP-712/191 from "Known
  limitations / Not implemented", and flip the CLAUDE.md / TODO.md entries.

## Remaining backlog (confirmed genuinely NOT implemented)

Grep-verified absent from source this session:
- **WebAuthn TPM / Apple attestation formats** — `verify_attestation` only
  does `packed` / `fido-u2f` / `none`. TPM needs certInfo/pubArea parsing +
  AIK cert chain; apple-anonymous needs the nonce cert extension check.
  Credential keys are already all-algs (EC2 P-256/384, Ed25519, RSA RS/PS).
- **pkix policy tree** — RFC 5280 §6.1 certificatePolicies / policyMappings /
  requireExplicitPolicy / inhibitAnyPolicy. Currently a *critical* policy
  extension is fail-closed (UnknownCriticalExtension), so there's no false
  positive; the gap is accepting legitimate policy-constrained chains. Bigger
  algorithm; test with openssl-generated certs.
- Other TODO.md Tier 2/3: Ed448/X448, ML-KEM/ML-DSA, PKCS#12, AES-GCM-SIV /
  AES-SIV, OCSP/CRL extension features (delta/indirect/dist-point), GHASH
  CLMUL (blocked on a MoonBit intrinsic).

## Environment gotchas (important for the next agent)

- **Tool-output buffering glitch in this remote container**: Bash/Read results
  frequently come back EMPTY and then surface (batched) a turn or two later.
  Workarounds used: run real work as `run_in_background: true` to a log file
  and Read the log; emit cheap `echo` "probe" calls to flush the backlog;
  rely on background-completion notifications. Don't trust an empty result as
  "no output" — re-read the log file. Verify pass/fail from the actual
  `Total tests:` line, never assume.
- **python `cryptography` is BROKEN** here (`ModuleNotFoundError:
  _cffi_backend`). `hashlib` works. **openssl 3.0.13 works** — use it for RSA
  keygen/sign/verify and PKCS#1/PSS vectors. openssl does NOT cover
  XChaCha20, keccak, or secp256k1 recovery → pin spec/library vectors for
  those.
- MoonBit idioms that bit us: `RsaPublicKey` (not `PublicKey`) with fields
  `{ n, e, n_bytes_len }`, `BigInt` in scope unqualified in `rsa.mbt`;
  blackbox tests call `@<pkg>.fn` and share helpers across `*_test.mbt` files
  in the same package; `try EXPR |> ignore catch { Pat => () } noraise { _ =>
  ... }` for "expect raise" tests; `moon fmt` rewrites `try…catch` onto one
  line. COSE alg → CBOR `Nint(v)` where alg = -(v+1) (RS256 -257 → Nint(256),
  PS256 -37 → Nint(36)). `derive(Show)` is NOT on `RsaPublicKey` (don't put it
  in a `derive(Show)` enum).
- Build/verify commands: `moon test -p mizchi/<mod>`, `moon test` (full),
  `moon test --target js|native`, `moon bench --release -p mizchi/<mod>`,
  `moon fmt`, `moon check`.

## Process constraints (standing)

- Develop/commit/push only on `claude/module-verification-security-Q8zdI`.
- Do NOT create PRs unless explicitly asked (this session: PR was explicitly
  requested for the EIP work).
- End commit messages with the session URL line.
- Do NOT put the model identifier in any committed artifact.
- GitHub tooling is restricted to `mizchi/moonbit-crypto`.
- No-false-positives is the project's core rule: a verifier may reject/defer
  unsupported input, but must never return trusted for something it can't
  fully check.
