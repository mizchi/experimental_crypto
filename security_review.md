# Security Review: experimental_crypto

Audit performed on commit `3f0b009`, scope is the entire workspace (13 modules).
Read-only review; no code changes accompany this document.

## Summary

| Severity | Count |
|---|---|
| **high** | 1 |
| **medium** | 9 |
| **low** | 13 |
| **info** (re-confirmed positive or known trade-off) | 9 |
| **Total** | 32 |

The biggest operational gap is **documentation**: nonce-reuse warnings,
parser limits, and "this is not constant-time" callouts are mostly
correct in the source but invisible to downstream callers. The
algorithmic implementations themselves (constant-time tag comparison,
DER Boolean/length/NULL/BIT STRING checks, RFC 7748 clamping, Ed25519
`S < L` malleability rejection, real OS CSPRNG backends) are in good
shape.

The four things most worth fixing next:

1. AEAD nonce-reuse warning (high) — single biggest foot-gun.
2. ASN.1 depth / length / canonicality (medium cluster) — parsers
   currently accept inputs they shouldn't.
3. KDF parameter caps on `verify_encoded` (medium) — DoS amplifier.
4. Two small constant-time hygiene fixes (`fe_eq`, x25519 all-zero
   check) — cheap, removes latent timing oracles.

---

## High

### 1. AEAD has no nonce-reuse warning in API docs

**Module**: `aead`
**Location**: `aead/aead.mbt:62-135`, `aead/README.mbt.md` (essentially empty)

`seal` / `seal_detached` take a `nonce : Bytes` with no warning that
reuse under the same key is catastrophic. For ChaCha20-Poly1305 a
single repeated `(key, nonce)` leaks the XOR of two plaintexts and
enables Poly1305 key recovery (forgery). For AES-GCM it trivially
leaks the GHASH authentication key. The README has no text. Bench
code reuses one fixed nonce across many encryptions, reinforcing the
bad pattern.

**Recommendation**: Doc comment + README section stating that nonce
MUST be unique per `(key, message)`. Optionally expose
`aead.seal_random_nonce(key, aad, plaintext) -> (nonce, ct||tag)` to
remove the foot-gun for typical callers.

---

## Medium

### 2. ASN.1 decoder has no recursion depth limit

**Module**: `asn1`
**Location**: `asn1/asn1.mbt:437-508`

`decode_value` recurses into nested SEQUENCE/SET without bounding
depth. A ~30-byte adversarial input can force unbounded native stack
growth. Affects every downstream parser (pkix, pkcs8).

**Recommendation**: Add `max_depth` parameter (default 32, matching
RustCrypto's `der` crate). Raise `Unsupported("nested too deep")`
past the limit.

### 3. ASN.1 length accepts up to ~2 GB — no max-input bound

**Module**: `asn1`
**Location**: `asn1/asn1.mbt:369-402`

`read_length` rejects only `nbytes > 4`, so a 4-byte long-form length
up to `0x7FFFFFFF` is accepted. A constructed wrapper containing a
huge declared length will reach `read_bytes(dec, length)` and
`Bytes::makei(length, ...)` — a 2 GB allocation from a few bytes.

**Recommendation**: Configurable `max_input_size` on `Decoder`
(default 16 MiB). Check `length > max_input_size` before any
allocation.

### 4. ASN.1 OID arc decoding silently overflows UInt

**Module**: `asn1`
**Location**: `asn1/asn1.mbt:181-194`

`value = (value << 7) | (b & 0x7F)` accumulates into a `UInt`. After
6+ continuation bytes the high bits silently wrap. An attacker can
encode an OID with prepended 7-bit zeros that decodes to the same
value as a canonical short form but with different DER bytes.

**Recommendation**: Detect overflow before the shift (`value >
UInt::max_value >> 7`) and raise `InvalidEncoding`. Better: use
`UInt64` for the accumulator.

### 5. ASN.1 OID non-minimal base-128 sub-identifier accepted

**Module**: `asn1`
**Location**: `asn1/asn1.mbt:181-194`

DER requires base-128 sub-identifiers to be minimal (no leading
`0x80`). Currently `0x80 0x01` and `0x01` both decode to arc value
`1`. Multiple distinct DER byte strings → same OID, breaking the
"DER is unique" invariant.

**Recommendation**: At start of each arc loop body, if `value == 0`
and the byte is `0x80`, raise `InvalidEncoding`.

### 6. ASN.1 INTEGER not validated for canonical encoding

**Module**: `asn1`
**Location**: `asn1/asn1.mbt:490`

INTEGER content stored as raw bytes with no canonicality check.
DER requires: length ≥ 1, and (leading byte, bit 7 of second byte)
must not both be 0x00/0 (positive redundancy) nor both 0xFF/1
(negative redundancy). `00 00 01`, `00 01`, and `01` all decode
without error.

**Recommendation**: In the `2U` branch of `decode_value`, reject
`length == 0` and the two-leading-bytes redundancy patterns per
X.690 §8.3.2.

### 7. pbkdf2 / scrypt / argon2 missing memory upper bound — `verify_encoded` DoS

**Module**: `pbkdf2`, `scrypt`, `argon2`
**Location**: `pbkdf2/pbkdf2.mbt:301-327`, `scrypt/scrypt.mbt:87-102`,
`argon2/argon2.mbt:241-254`

When KDF parameters come from attacker-controlled PHC strings, an
attacker can pick astronomically large costs. argon2 has no upper
bound on `m_cost`. scrypt's `log_n ≤ 30` allows 128 GB scratch at
`r=1`. pbkdf2's `dk_len` is unbounded and `(dk_len + h_len - 1) /
h_len * h_len` can overflow signed Int to negative.

**Recommendation**:
- argon2: cap `m_cost` (e.g. 4 GiB), `t_cost` (e.g. 64), configurable.
- scrypt: `log_n ≤ 24`, `r ≤ 32`, `p ≤ 16` for default-safe.
- pbkdf2: `dk_len ≤ 64 MiB`; bound-check `dk_len / h_len` before
  multiplying.

### 8. x25519 `AllZeroSharedSecret` check uses early-exit `break`

**Module**: `x25519`
**Location**: `x25519/x25519.mbt:140-150`

`if out[i].to_int() != 0 { break }` makes execution time depend on
the position of the first non-zero byte in the shared secret —
leaks bits of the secret to a remote latency observer.

**Recommendation**: Use the OR-XOR pattern from
`aead.constant_time_eq`: `let mut acc = 0; for i { acc = acc |
out[i].to_int() }`. No early break.

### 9. ed25519 `fe_eq` short-circuits

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt:807-816`

Returns false at the first non-matching byte. Currently called from
`point_decompress` and `ed_points_equal`, both on **public** inputs,
so not directly exploitable today. But if `point_decompress` is ever
applied to secret material in a future feature, the leak becomes
real.

**Recommendation**: One-line change to OR-XOR over all 32 bytes,
matching `aead.constant_time_eq`.

### 10. ed25519 scalar multiplication is variable-time double-and-add (RESOLVED)

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt`

`ed_scalar_mult_point` is now a fixed-iteration double-and-always-add
ladder with constant-time `ed_point_cmov`. Scalar bits are extracted
from a 32-byte little-endian buffer (so no @bigint length leak), and
both `ed_point_double` and `ed_point_add` execute on every iteration
regardless of the bit value.

Root cause for the two prior failed attempts was a latent issue in
`ed_point_double`: when fed the doubled-identity coordinates
`(0, -1, -1, 0)`, `fe_sqr(p.x)` returns the "p"-encoded zero (limbs
maxed); `fe_add(a, b)` then drives one limb above `two_p_limb` and
`fe_neg(ab)` / `fe_sub(g, c2)` underflow in `UInt64`. The variable-time
ladder never hit this state because it skipped leading zero bits. Fix
was to `fe_carry_full` `ab` and `c2` before they are subtracted from.

Cost (native, M-class): sign +27 %, verify +37 %, derive_pk +24 %.

---

## Low

### 11. AES T-table is cache-timing side channel (documented)

`aead/aes.mbt:1-9` explicitly marks NOT constant-time. Co-located
attackers can recover key bits via cache observation. Documented
but README has no callout — add one.

### 12. pbkdf2 uses `unsafe_get` / `unsafe_set` with derived indices

`pbkdf2/pbkdf2.mbt:62-103, 137-178, 320-367`. All current callers
bound the index by literals or pre-validated lengths, but a
refactor could silently introduce OOB reads in native builds. Bench
gain from `unsafe_*` is modest; consider replacing with bounds-
checked accessors or adding debug assertions.

### 13. PEM base64 decode does not enforce padding

`pem/pem.mbt:103-105`. Lenient by default. RFC 7468 strict mode
requires padded base64. Multiple distinct PEM strings can decode to
the same bytes. Harms byte-equality cache keys.

**Recommendation**: Expose `decode_strict` per RFC 7468.

### 14. pem `decode_all` accepts arbitrarily large input

`pem/pem.mbt:37-109`. No size cap. Multi-GB input → OOM.

**Recommendation**: Optional `max_input_size` (default 16 MiB).

### 15. pem `LabelMismatch` reporting

`pem/pem.mbt:101`. Defensive only — `pkcs8.parse_pem` re-checks the
label. No action.

### 16. pkix does NOT verify cert chain or signature

`pkix/pkix.mbt:434-444`. README explicitly says "parser, not a
verifier." Listed for visibility — caller MUST not treat parse
success as trust.

**Recommendation**: Doc comment on `parse_certificate` reiterating
"does NOT verify the signature."

### 17. pkix `expect_integer_small` mis-handles negative INTEGERs

`pkix/pkix.mbt:111-121`. `value = (value << 8) | bytes[i].to_int()`
treats top-bit-set byte sequences as positive. Used only for cert
version (0/1/2) today — safe by accident. Latent bug if reused
elsewhere.

**Recommendation**: Add sign extension, or tighten the contract to
"1-byte INTEGER, value 0..2".

### 18. pkcs8 attributes preserved in input order (not DER SET order)

`pkcs8/pkcs8.mbt:168-183`. DER SET requires lexicographic ordering;
the serializer preserves input order. Round-trip from a non-
canonical input re-emits non-canonical bytes.

**Recommendation**: Sort by encoded form before serialization, or
expose `serialize_der_canonical`.

### 19. scrypt `parse_phc` accepts non-canonical integers

`scrypt/scrypt.mbt:379-394`. `@strconv.parse_int` accepts `+15` and
similar. PHC string canonicality not enforced.

**Recommendation**: Reject if parameter contains anything other than
`[0-9]+`.

### 20. argon2 `parse_phc` accepts duplicate parameters (last wins)

`argon2/argon2.mbt:158-223`. A malicious PHC like
`...m=8,t=2,p=1,m=99999999999...$...$...` is accepted with the last
`m` value. Same DoS family as finding 7.

**Recommendation**: Track per-param `_set` booleans; reject
duplicates.

### 21. pbkdf2 `num_blocks * h_len` integer overflow

`pbkdf2/pbkdf2.mbt:327-330`. `(dk_len + h_len - 1) / h_len`
overflows for `dk_len` near `Int::max_value`. Caller is trusted
today.

**Recommendation**: Reject `dk_len > 2^30` (RFC 8018 caps at
`(2^32 - 1) × h_len`).

### 22. scrypt `n.to_uint64()` overflow at the `log_n` boundary

`scrypt/scrypt.mbt:42`. `n = 1 << params.log_n`. With `log_n=31`
this would be negative; the cap of 30 saves us. Latent if the cap
is loosened.

**Recommendation**: Compute `n` as `UInt64` directly:
`let n_u64 : UInt64 = 1UL << params.log_n`.

### 23. scrypt allocates `n × words` UInt32 — silent OOM at `log_n=30`

`scrypt/scrypt.mbt:128-129`. At `log_n=30, r=8` the V buffer is
1 TiB. `FixedArray::make` will OOM. Same family as finding 7.

**Recommendation**: Add `n × words ≤ Int::max_value / 4` check, and
cap `block_size × p` at e.g. 1 GiB.

### 24. aead `chacha20_xor` `abort` on impossible path

`aead/aead.mbt:194-225`. Unchecked path has a `match { Err(_) =>
abort(...) }` that should be unreachable if validation is correct.

**Recommendation**: Convert to `raise UnsupportedAlgorithm` so
callers can recover.

---

## Info (re-confirmation of known positive properties or accepted trade-offs)

| # | Item | Note |
|---|---|---|
| 25 | `crypto_bigint` delegates to `@bigint` | Documented NOT constant-time. |
| 26 | ed25519 scalar mod L on `@bigint` | Documented; roadmap. |
| 27 | u64 mul on wasm/JS not formally constant-time | Documented. |
| 28 | DER strict checks already in place | Boolean 0x00/0xFF, indefinite length rejected, long-form minimal, NULL length=0, BitString unused_bits ≤ 7. |
| 29 | AEAD tag compare is constant-time | OR-XOR pattern, no early termination. |
| 30 | ed25519 enforces `S < L` (anti-malleability) | Both `verify` and `verify_strict`. |
| 31 | x25519 RFC 7748 clamp + high-bit mask applied | Per §5. |
| 32 | getrandom backends are real OS CSPRNGs | `crypto.getRandomValues` (JS), `arc4random_buf` / `getrandom(2)` / `BCryptGenRandom` (native). No seeded PRNG fallback. Unknown-platform branch returns empty bytes → `Insufficient` on the MoonBit side (safe failure mode). |

---

## Cross-cutting observations

1. The constant-time primitives that exist (`aead.constant_time_eq`,
   `argon2.ct_eq_bytes`, `scrypt.ct_eq_bytes`) are correct. Two
   nearby paths (`x25519` all-zero check, `ed25519.fe_eq`) should be
   converted to the same OR-XOR pattern for hygiene.

2. The DER parser is strict in some places (Boolean, length, NULL,
   BitString) but lenient in others (OID arc minimality, OID UInt
   overflow, INTEGER canonicality, recursion depth, total input
   size). Fixing this consistently would close a cluster of medium-
   severity issues at once.

3. The KDF modules (`pbkdf2`, `scrypt`, `argon2`) all accept attacker-
   controlled parameters in their `verify_encoded` paths but apply
   no upper bound on memory cost. Closing this is a one-line cap per
   module and removes a DoS amplifier.

4. The biggest single user-facing risk is nonce reuse in `aead`
   (finding 1). One README paragraph and a doc comment on `seal`
   would dramatically reduce the chance of catastrophic misuse.
