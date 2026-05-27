# `mizchi/proofs` — cross-cutting model-checked primitives

Proof-carrying versions of small leaf functions that don't naturally
belong to any single library. Properties are stated as `proof_ensure` /
`proof_require` postconditions / preconditions that `moon prove`
discharges through Why3 and an SMT solver (Z3 by default; CVC5 /
Alt-Ergo are optional).

The aim is **not** to re-derive cryptographic theorems. SMT cannot prove
"this hash is collision-resistant" or "this scalar multiplication
implements the group law." What it *can* prove is concrete arithmetic,
bit, and bounds invariants on small leaf functions — the foundations
that constant-time and canonical-form code relies on.

## Where proofs live

| Style | Location | Used for |
|---|---|---|
| Per-library proof sub-package | `<lib>/<name>/` (e.g. `pem/wrap/`) | invariants that anchor a specific library's behavior |
| Cross-cutting primitives | `proofs/` (this package) | helpers that span libraries or have no concrete caller yet |

Per-library proofs are the default. `moon prove` lowers the whole
package to Why3, so any package that mentions a type the frontend can't
translate (`Array`, complex sums, `BigInt`, etc.) cannot enable proofs
package-wide. The workaround is a leaf sub-package next to the library
that exposes only the math step and is the only place that turns on
`proof-enabled`. The host library imports it like any other dep.

`pem/wrap/` demonstrates this pattern: it lives inside `pem/`, holds the
proven base64 line-wrap helper, and `pem.encode` calls it. The full
`pem` package keeps using `Array` types and stays out of the Why3
frontend.

## What is verified here (cross-cutting)

| Function | Property |
|---|---|
| `abs(x)` | result ≥ 0 ∧ (result == x ∨ result == −x) — smoke test |
| `mod_pos(a, m)` | result ∈ [0, m) for any sign of `a`, given m > 0 |
| `hex_value(c)` | valid hex char → result ∈ [0, 16) |
| `ct_select(mask, a, b)` | mask ∈ {0, 1} → branch-free select returns `a` or `b` |
| `reduce_once(a, m)` | freeze step: `0 ≤ a < 2m` → result ∈ [0, m) |

`ct_select` and `reduce_once` are the building blocks under constant-time
scalar multiplication in `@p256` / `@p384` / `@secp256k1`, and under the
planned const-time field-arithmetic rewrite in `@ed25519`.

## Per-library proof sub-packages

| Package | Function | Property |
|---|---|---|
| `pem/wrap` | `pem_next_chunk_len(remaining, cap)` | RFC 7468 §3 strict line cap; `encode`'s wrap loop never emits a line longer than 64 chars, and terminates as long as `cap > 0` |
| `aead/wrap` | `ghash_zero_pad_len(len, block_size)` | NIST SP 800-38D §6.5 GHASH zero-pad length ∈ [0, block_size) AND `(len + result) % block_size == 0` — wired into `aead.poly1305_aead_tag` |
| `aead/wrap` | `pkcs7_pad_len(plaintext_len, block_size)` | RFC 5652 §6.3 PKCS#7 padding length ∈ [1, block_size] AND `(plaintext_len + result) % block_size == 0` — spec for future encrypt-side wiring |
| `aead/wrap` | `aes_round_count(key_bits)` | FIPS 197 §5.1 Table 4: `Nr ∈ {10,12,14}` for `key_bits ∈ {128,192,256}` |
| `aead/wrap` | `aes_key_word_count(key_bits)` | FIPS 197 §5.2: `Nk ∈ {4,6,8}` for `key_bits ∈ {128,192,256}` |
| `hkdf/wrap` | `hkdf_block_count(L, hash_len)` | RFC 5869 §2.3 block count ∈ [1, 255] given L ≤ 255·HashLen — wired into `hkdf.expand` |
| `pbkdf2/wrap` | `pbkdf2_block_count(dk_len, h_len)` | RFC 8018 §5.2 block count ∈ [1, ⌈dk_len/h_len⌉] with `(N-1)·h_len < dk_len ≤ N·h_len` — spec for `pbkdf2.derive` |
| `pbkdf2/wrap` | `pbkdf2_total_output_bytes(dk_len, h_len)` | Block-aligned scratch size = `block_count × h_len`. Anchors consistency with `pbkdf2_block_count` |
| `bip32/wrap` | `is_hardened_from_msb(msb)` | BIP-32 §3 hardened-bit dispatch: `ser32(i)[0] >= 0x80` ⇔ hardened. Returns `{0,1}` |
| `bip39/wrap` | `mnemonic_word_count(ent_bits)` | BIP-39 §3 mnemonic length ∈ {12,15,18,21,24} for entropy ∈ {128,160,192,224,256} bits |
| `hash/wrap` | `sha256_pad_len(msg_bytes)` | FIPS 180-4 §5.1.1 SHA-256 padding length ∈ [9, 72] AND `(msg_bytes + result) % 64 == 0` |
| `hash/wrap` | `sha512_pad_len(msg_bytes)` | FIPS 180-4 §5.1.2 SHA-512 padding length ∈ [17, 144] AND `(msg_bytes + result) % 128 == 0` |
| `totp/wrap` | `totp_digit_modulus(digits)` | RFC 4226 §5.3 / RFC 6238 HOTP-truncation modulus ∈ {10^6, 10^7, 10^8} for digits ∈ {6, 7, 8} |
| `scrypt/wrap` | `scrypt_pbkdf_blocks(dk_len, h_len)` | RFC 7914 §2 step-4 PBKDF2 block count for the final dkLen-byte derivation |
| `getrandom/wrap` | `getrandom_chunk_len(remaining, cap)` | OS CSPRNG syscall chunking — `min(remaining, cap)` with caller-cap honored (Linux 256B, macOS 4096B, …) |
| `argon2/wrap` | `argon2_segment_length(m_cost, lanes)` | RFC 9106 §3.2: `floor(m_cost / (4·lanes)) ≥ 2` with `4·lanes·segment_length ≤ m_cost < 4·lanes·(segment_length+1)` |
| `jwt/wrap` | `base64url_unpadded_len(input_bytes)` | RFC 4648 §5 / RFC 7515: no-padding base64url char count = `ceil(4·input_bytes / 3)` |
| `pgp/wrap` | `pgp_packet_length_octets(body_len)` | RFC 9580 §4.2.1 new-format packet length encoding ∈ {1, 2, 5} octets |
| `asn1/wrap` | `der_length_prefix_size(n)` | X.690 §8.1.3 DER length-prefix octet count ∈ [1, 5] — spec for `asn1.write_length` |
| `asn1/wrap` | `der_oid_arc_byte_count(arc)` | X.690 §8.19 base-128 varint byte count ∈ [1, 5] — spec for OID encoder scratch sizing |
| `asn1/wrap` | `der_length_prefix_size_monotone(a, b)` | Monotonicity: `a ≤ b ⇒ size(a) ≤ size(b)`. Anchors loop-sizing safety |
| `asn1/wrap` | `der_oid_arc_byte_count_monotone(a, b)` | Monotonicity of OID arc byte count |
| `asn1/wrap` | `der_length_payload_bytes_after_indicator(indicator)` | Reader-side companion to `der_length_prefix_size`: payload octets ∈ [0, 4] following X.690 §8.1.3.5 indicator byte |
| `asn1/wrap` | `der_length_round_trip(n)` | Writer ↔ reader spec-level alignment for the X.690 §8.1.3 length encoding |

The "spec" entries (`pkcs7_pad_len`, `der_length_prefix_size`,
`is_hardened_from_msb`, `mnemonic_word_count`) are helpers the host
library hasn't called yet — the proof anchors the contract any future
caller will rely on.

### Multi-solver strategy

`moon prove`'s default Why3 strategy only invokes Z3, which times out on
modular-arithmetic postconditions like `(x + result) % block_size == 0`
(Why3's `mod_` lowering doesn't reach the Euclidean axiom within Z3's
default budget). `proofs/setup.sh` provisions Alt-Ergo (opam) alongside
the nix-supplied CVC5 / Z3, then emits a `proofs/why3.conf` with a
`MoonBit_Auto` strategy that tries `Z3 → CVC5 → Alt-Ergo`. CVC5 1.3.3
discharges both block-alignment goals in well under a second.

Run prove through the wrapper to pick up this config automatically:

```bash
bash proofs/prove.sh                  # all wrap packages + proofs/
bash proofs/prove.sh aead/wrap        # single sub-package
```

Or pass `--why3-config proofs/why3.conf` directly to `moon prove`.

## Setup

`moon prove` requires Why3 1.7.2 and at least one SMT solver.

### Nix (recommended)

The repo ships a `flake.nix` that pins moonbit, opam, z3, cvc5,
alt-ergo, and the OCaml build deps Why3 needs. Enter the dev shell:

```bash
nix develop --impure
```

The shell hook sets `OPAMROOT=$PWD/.opam` and auto-activates the opam
switch if one exists. First time only, install Why3 into it:

```bash
bash proofs/setup.sh
```

With `direnv` installed, the bundled `.envrc` enters the shell
automatically on `cd`.

### Manual (no nix)

```bash
brew install opam z3                   # one-time, system-wide
bash proofs/setup.sh
```

`setup.sh` initialises a project-local opam switch
(`./.opam/moonbit-crypto`) with OCaml 4.14.2 + Why3 1.7.2 + zarith, then
runs `why3 config detect` so the discovered solvers (z3, plus cvc5 /
alt-ergo if present) are registered. After that, every shell needs:

```bash
export OPAMROOT="$PWD/.opam"
eval "$(opam env --switch=moonbit-crypto --set-switch)"
```

(or use the nix devShell, which does this for you).

## Running the prover

```bash
eval "$(opam env --switch=moonbit-crypto --set-switch)"
cd proofs && moon prove
```

Output lands in `_build/verif/proofs.proof.json` with per-goal solver
attribution and step counts. A non-zero exit code means at least one
verification condition failed.

## Adding a new proof

Three rules:

1. Mark the package as proof-enabled in `moon.pkg`:

   ```pkl
   options(
     "proof-enabled": true
   )
   ```

2. Write the contract in the function signature:

   ```moonbit
   pub fn name(args) -> Ret where {
     proof_require: <Bool expression>,
     proof_ensure: result => <Bool expression>,
   } { ... }
   ```

3. Keep each clause on a single line — `proof_require` and `proof_ensure`
   bodies do not currently parse across line breaks.

For richer proofs (predicates, lemmas, abstract models), split helpers
into a sibling `*.mbtp` file. See
`https://github.com/moonbitlang/moonbit-agent-guide/tree/main/moonbit-proof`
for the full pattern.

## What is *not* checked here

Cryptographic correctness theorems (group law, hash properties, AEAD
INT-CTXT, RFC 6979 determinism modulo subgroup order, etc.) are out of
scope for `moon prove`. Those continue to be tracked through RFC test
vectors and cross-implementation comparison, not symbolic proof.
