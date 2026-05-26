# Security Review #2: moonbit-crypto

Audit performed on commit `fe49bd5`. Scope: self-impl crypto correctness
(SHA-256 / SHA-512 / BLAKE2b / ChaCha20 / AES T-table), padding /
endianness / counter wrap, memory zeroize, panic paths, corner cases.

Builds on `security_review.md` (commit `3f0b009`). Findings already
covered there are not repeated; the high-1 + medium-9 cluster fixed
in `bfc48f1` / `5b9d007` / `9c204e0` / `c6b06d6` was re-verified to
match its respective recommendation and is no longer reported.

## Summary

| Severity | Count |
|---|---|
| **high** | 0 |
| **medium** | 6 |
| **low** | 12 |
| **info** (re-confirmed positive or accepted trade-off) | 7 |
| **Total** | 25 |

The self-impl SHA-256 / SHA-512 / BLAKE2b / ChaCha20 cores match the
reference values bit-for-bit (round constants, IV, sigma schedule,
endianness, padding all verified by inspection against RFC 6234 /
FIPS 180-4 / RFC 7693 / RFC 8439). AES T-table values and key
schedule (incl. AES-256 SubWord-every-4-words step) check out. The
substantive issues are all at the **input-bound / counter-wrap /
memory-allocation** edge, not in the round functions.

Top items to fix next:

1. AEAD per-(key, nonce) maximum-output cap (medium cluster) —
   ChaCha20 counter wraps at 2^32 blocks, AES-GCM at 2^32-2 blocks;
   no check today.
2. scrypt allocation overflow at the `log_n=24, r=32` corner
   (medium) — `n * 32r` overflows `Int` long before the cap fires.
3. AES key-schedule abort on non-{16,32} key length should become
   a `raise` so callers can recover (medium).
4. Memory-wipe hygiene on intermediate secrets (low cluster) —
   none of the modules zeroize ipad/opad state, one-time Poly1305
   key, ed25519 r / a_scalar / prefix, or AES round keys.
5. No fuzz harnesses exist for pbkdf2 / argon2 / scrypt (low) —
   PBKDF2 boundary cases (salt_len near 64, dk_len near h_len
   multiple) and Argon2 single-pass vs multi-pass behaviour are
   uncovered.

---

## Medium

### 1. ChaCha20 counter silently wraps at 2^32 blocks

**Module**: `aead`
**Location**: `aead/chacha20.mbt:230`, `aead/aead.mbt:114-127`

`chacha20_xor_inner` increments `ctr : UInt` per 64-byte block with
no overflow check. After `2^32 - 1` blocks (≈ 256 GiB of plaintext
under one (key, nonce)) the counter wraps to 0 and the **same
keystream is produced again**. RFC 8439 §2.8 explicitly forbids
this; long-running streams that exceed the cap **leak the XOR of
two plaintexts** without ever reusing the nonce visibly.

**Risk**: Confidentiality breach for the wrapped blocks. Plus
Poly1305 still produces a valid tag because the MAC is computed
over the wrapped ciphertext that the receiver also decrypts with
the wrapped keystream, so the failure is silent.

**Recommendation**: In `chacha20_poly1305_seal` / `_open`, reject
`plaintext.length() > (2^32 - 1) * 64 - 1` (= `0x3FFFFFFFFE0`, i.e.
274,877,906,880 bytes) up front. Or, cheaper, reject if the loop
would step counter past `0xFFFFFFFF` — i.e. `n > (2^32 - 1) * 64`.

### 2. AES-GCM has no plaintext / ciphertext length cap

**Module**: `aead`
**Location**: `aead/gcm.mbt:282-309, 312-365`

`aes_ctr_xor` increments the bottom 32 bits of the counter with
`(ctr + 1) & 0xFFFFFFFF`. NIST SP 800-38D §5.2.1.1 mandates that no
more than `2^39 - 256` bits (= 64 GiB minus 32 B) of plaintext be
processed under a single (key, IV). Past that point, the counter
recycles values that were already used for J0 / the first keystream
block of another invocation, breaking confidentiality. There is no
cap and no per-call accounting today.

**Risk**: Same as #1 above for very long messages, plus tag
collision potential because GHASH(H, A, C) is a fixed polynomial in
H — feeding 2^32 blocks gives an attacker enough algebraic
structure for tag forgeries.

**Recommendation**: Reject `plaintext.length() > (1 << 36) - 32`
(64 GiB - 32 B) in `aes_gcm_seal`. The check is one comparison.

### 3. AES `aes_key_schedule` aborts on bad key length

**Module**: `aead`
**Location**: `aead/aes.mbt:157-163`

```moonbit
let (nk, nr) = match key_len {
  16 => (4, 10)
  32 => (8, 14)
  _ => abort("aes_key_schedule: bad key length")
}
```

This `abort` is reachable only via `aead.seal` / `open`, which
*do* `validate_key_nonce` for ChaCha20 but for AES-GCM the
validation lives in `aes_gcm_seal` / `aes_gcm_open` (`gcm.mbt:319,
377`). Both validate `key.length() != key_len` (16 or 32) before
calling `aes_key_schedule`, so the abort is unreachable on the
public path **today**. However, `aes_encrypt_block` and
`aes_key_schedule` are package-internal but called from
`gcm.mbt:329, 387, 275, 406` after validation — fine. The risk is
that a future refactor (e.g. exposing a generic block-cipher
trait) skips the validation and triggers an abort on
caller-controlled input.

**Recommendation**: Convert to `raise AeadError::InvalidKeySize`
(threading the `raise` through `aes_encrypt_block` and
`aes_ctr_xor`), or at minimum add a comment "MUST be preceded by
length validation; reachable only if invariant breaks."

### 4. scrypt `n * 32 * r` overflows Int before the `log_n` cap fires

**Module**: `scrypt`
**Location**: `scrypt/scrypt.mbt:87-103, 125-135`

`validate_params` caps `log_n ≤ 24` and `r ≤ 32`. ROMix allocates
`FixedArray::make(n * words, 0U)` where `words = 32 * r` and
`n = 1 << log_n`. At the corner `log_n = 24, r = 32`:

```
n * words = 2^24 * 32 * 32 = 2^34
```

which exceeds MoonBit's signed `Int` range (≈ 2^31). The
multiplication silently wraps to a negative value before reaching
`FixedArray::make`, producing either an abort (negative size) or
a small allocation followed by out-of-bounds writes depending on
the runtime backend. Finding #23 from review #1 was about
`log_n=30, r=8`; closing the same family at the current caps is
not complete.

**Risk**: Crash on the wasm/JS backends; potential native UB if
the runtime accepts a negative size and reinterprets. Triggered
by attacker-controlled `verify_encoded` parameters that pass the
individual-parameter caps.

**Recommendation**: Add a combined check after the per-parameter
caps, e.g.

```moonbit
let n_u64 : UInt64 = 1UL << params.log_n
let alloc_words = n_u64 * (32UL * params.r.to_uint64()) * params.p.to_uint64()
if alloc_words > 0x40000000UL { // ≤ 4 GiB scratch
  raise InvalidParams("n × 32r × p too large")
}
```

### 5. SHA-256 self-impl assumes input length fits in `Int`

**Module**: `pbkdf2`
**Location**: `pbkdf2/pbkdf2.mbt:107-129, 132-178, 182-214`

`sha256_finalize_with_tail` encodes `total_bits = prefix_bits +
tail_len.to_uint64() * 8UL` as 64-bit big-endian bits. SHA-256
specifies a 64-bit length field, so for any input ≤ 2^61 bytes
this is correct. However:

1. `prefix_bits + tail_len * 8` is `UInt64` addition with **no
   overflow check**. For attacker-supplied inputs > 2^61 bytes the
   length field wraps and the digest becomes attacker-influenced
   in a way that breaks collision resistance for that single
   monstrous input. Not exploitable in practice (no MoonBit
   process holds 2 EiB of data), but worth a one-line cap to
   match RFC 6234.
2. `sha256_hash_bytes` and `hmac_sha256_compute` accept `data :
   Bytes` whose `length() : Int` is signed and limited to ~2 GiB.
   The `* 8UL` multiplication is safe.

**Recommendation**: Either document the "≤ 2 GiB" bound as a
property of the MoonBit `Bytes` type and call it a day, or reject
`data.length() > 0x1FFFFFFFFF` (2^61 bits = 2^58 bytes) in
`sha256_hash_bytes`.

### 6. AES key schedule allocates `total_words = 4 * (nr + 1)` Int — no width check

**Module**: `aead`
**Location**: `aead/aes.mbt:157-198`

For a properly-validated key (16 or 32 bytes), `nr` is 10 or 14
and `total_words` is 44 or 60 — trivially safe. But the round
constants table `aes_rcon` has 11 entries (indices 0..10) and is
indexed by `i / nk` which reaches `i / nk = (total_words - 1) /
nk`. For AES-128 (`nk=4`, `total_words=44`): `43 / 4 = 10` — last
valid index. For AES-256 (`nk=8`, `total_words=60`): `59 / 8 = 7`
— well in-range. So `aes_rcon` indexing is correct **only** for
the two supported key sizes.

A refactor that extends `aes_key_schedule` to AES-192 (`nk=6,
nr=12, total_words=52, max i/nk = 51/6 = 8`) would also still fit.
But e.g. AES-1024 hypothetically would index past the 11-entry
table and silently OOB.

**Risk**: Latent. Today the abort at line 162 prevents this. Worth
a comment so a future maintainer doesn't reuse `aes_rcon` without
also extending it.

**Recommendation**: Comment block above `aes_rcon` stating "Indexed
by `i / nk` for AES-{128,192,256}; if adding a new key size, also
extend the table." Optionally add a debug `assert i / nk < 11`.

---

## Low

### 7. No memory wipe of one-time Poly1305 key

**Module**: `aead`
**Location**: `aead/aead.mbt:196-199, 161-172`

`poly1305_key_gen` returns the 32-byte one-time MAC key as a fresh
`Bytes`. After `poly1305_aead_tag` returns, the GC controls when
that buffer is reclaimed. The key remains in memory until then.
MoonBit has no explicit `secure_zero` primitive, but for Bytes
backed by a FixedArray the caller could overwrite indices `0..31`
before returning.

**Risk**: Low — exposure only via heap dump / cold-boot. Listed
for hygiene.

**Recommendation**: After tag computation, overwrite the otk
buffer (if Bytes is mutable on the underlying FixedArray) or
explicitly allocate it as `FixedArray[Byte]` and zero before
returning. Same pattern applies to `chacha20_block`'s `ks` scratch
buffer (cleared by being overwritten next loop, but the final
iteration's keystream tail lingers).

### 8. No memory wipe of HMAC ipad/opad state in pbkdf2

**Module**: `pbkdf2`
**Location**: `pbkdf2/pbkdf2.mbt:226-252`

`hmac_sha256_init` computes `inner_state` / `outer_state` from the
password-derived ipad/opad and returns them inside `HmacSha256Ctx`.
`pbkdf2_sha256` uses the ctx for every block; after returning, the
state is reachable until GC. The state words are derivable from
the password plus the public ipad/opad constants, so anyone with
read access to the digest state can mount an offline dictionary
attack as if they had the password's HMAC key.

**Risk**: Low — same heap-dump / cold-boot scenario as #7.

**Recommendation**: Provide an `HmacSha256Ctx::clear` that zeroes
the two `FixedArray[UInt]` fields, and call it in `pbkdf2_sha256`
before returning.

### 9. No memory wipe of ed25519 sign-side secrets

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt:106-139`

`sign` materializes `a_scalar`, `prefix`, `r`, and `r_hash` (the
SHA-512 of `prefix || message`). All four are secret-derived. None
is wiped before `sign` returns. `r_hash`, `prefix`, and the SHA-512
context `ctx` retain bytes long enough for the GC to relocate
them, and `BigInt` instances `a_scalar`, `r`, `k` are entirely
opaque (no programmatic clear is even possible without breaking
the type system).

**Risk**: Low — exposure only via memory inspection. Documented
known limit of doing public-key crypto in a managed-runtime
language.

**Recommendation**: Where possible (FixedArray-backed secrets),
zero before return. For BigInt secrets, accept the limit and
document it in the module README.

### 10. ed25519 `point_decompress` early-exits on canonical-y check

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt:1050-1055`

```moonbit
for i in 0..<32 {
  if y_round[i] != y_bytes[i] {
    return None
  }
}
```

Loop exits at the first differing byte. Both call sites
(`verify_strict`, `verify`) feed public R and A, so not directly
exploitable — same status as `fe_eq` was in review #1 finding 9
before that fix.

**Recommendation**: For symmetry with the OR-XOR fix already
applied to `fe_eq` and the x25519 zero check, accumulate the
difference and compare once:

```moonbit
let mut acc = 0
for i in 0..<32 { acc = acc | (y_round[i].to_int() ^ y_bytes[i].to_int()) }
if acc != 0 { return None }
```

### 11. ed25519 `ed_points_equal` uses short-circuit `&&`

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt:1015-1022`

```moonbit
fe_eq(lhs1, rhs1) && fe_eq(lhs2, rhs2)
```

`&&` is short-circuit, so if `fe_eq(lhs1, rhs1)` returns `false`
the second `fe_eq` is skipped. `fe_eq` itself was fixed in commit
`c6b06d6` to be branch-free, but the wrapper re-introduces a
timing distinction between "x coordinates differ" and "y
coordinates differ." Inputs are public on every current call
site so not exploitable, but undoes the hygiene win.

**Recommendation**: `fe_eq(lhs1, rhs1) & fe_eq(lhs2, rhs2)` if
MoonBit's `&` works on `Bool`, otherwise sum the two booleans
into an Int and compare to 2.

### 12. ed25519 `fe_is_zero` short-circuits

**Module**: `ed25519`
**Location**: `ed25519/ed25519.mbt:830-838`

```moonbit
fn fe_is_zero(a : Fe) -> Bool {
  let bytes = fe_to_bytes(a)
  for i in 0..<32 {
    if bytes[i].to_int() != 0 { return false }
  }
  true
}
```

Used by `recover_x` (point decompression) on public points only.
Same hygiene argument as #10 / #11.

**Recommendation**: OR-accumulate, single comparison.

### 13. ChaCha20-Poly1305 `tag.length() != 16` returns `AuthenticationFailed`, not a length error

**Module**: `aead`
**Location**: `aead/aead.mbt:181-185`

```moonbit
if tag.length() != 16 {
  raise AuthenticationFailed
}
```

When the caller passes a wrong-length tag (e.g. 12 bytes), the
error returned is indistinguishable from a tag-mismatch on a
16-byte tag. Same in `aes_gcm_open` (gcm.mbt:382). For most use
cases this is fine — the tag length is part of the protocol and
mis-sized tags are programming errors. But silently lumping them
with cryptographic failure makes debugging harder and could mask
a downstream framing bug.

**Recommendation**: Add a separate `InvalidTagSize(expected~:Int,
got~:Int)` variant, mirroring `InvalidKeySize` /
`InvalidNonceSize`. Or document that any non-16 tag length is
treated as a failed authentication.

### 14. pbkdf2 `u1_msg` buffer is reused as scratch — leaks last salt+INT bytes

**Module**: `pbkdf2`
**Location**: `pbkdf2/pbkdf2.mbt:341-365`

`u1_msg` is allocated once with `salt_len + 4` capacity and reused
across the `for blk` loop, only overwriting bytes
`[salt_len..salt_len+4]` for the per-block counter. The salt
itself stays in the buffer for the lifetime of the call (it's
public, so OK), and at the end the last `INT(num_blocks)` value
lingers (also public). The risk surface is zero in normal
operation; the comment is for completeness — this is one of the
few buffers that does *not* hold a secret.

**No action.** Listed so the next reviewer doesn't flag it.

### 15. argon2 `parse_phc` accepts non-canonical integer encodings

**Module**: `argon2`
**Location**: `argon2/argon2.mbt:186-206`

`@strconv.parse_int(v)` accepts leading `+`, leading zeros, and
multiple zero forms (`0`, `00`, `000` all decode to 0). PHC string
canonicality requires `[0-9]+` only. Same family as review #1
finding 19 (scrypt), now applied to argon2 as well.

**Recommendation**: Add a per-token regex check `^[1-9][0-9]*$|^0$`
(or hand-rolled equivalent) before passing to `parse_int`.

### 16. argon2 `parse_phc` accepts negative integer parameters

**Module**: `argon2`
**Location**: `argon2/argon2.mbt:191-208`

`@strconv.parse_int` returns a signed `Int`, and the only sanity
check is `m_cost < 0 || t_cost < 0 || parallelism < 0`. So
`m=-2147483648` would be rejected, but `m=-1` is too — actually,
the check is present so this is OK. Worth confirming the check
also rejects very large positive values that wrap to negative
inside `parse_int` (it does, per MoonBit's `parse_int` behavior).

**No action** — confirmed safe. Re-listed because review #1's
finding 20 (duplicate `m=`) was about a different DoS.

### 17. BLAKE2b `total_len.to_uint64()` ignores `t_high`

**Module**: `argon2`
**Location**: `argon2/argon2.mbt:1969-1978`

The top-level `blake2b` function passes `t_high = 0UL` to every
compression call and never updates a 128-bit counter. For inputs
up to 2^64 bytes (≈ 18 EiB) this is correct because the low 64
bits never wrap. MoonBit's `FixedArray::length` is `Int`-bounded
(~2 GiB), so the high half is in practice always zero.

If `blake2b` were ever exposed as a streaming hash for huge
inputs, the counter logic would need a real 128-bit increment.

**Recommendation**: Comment that BLAKE2b here is one-shot and
input-length-bounded by `Int`; if ever made streaming, the
counter needs a carry into `t_high`.

### 18. ChaCha20 scratch `ks` buffer is shared across blocks but holds key-derived bytes between iterations

**Module**: `aead`
**Location**: `aead/chacha20.mbt:218-230`

```moonbit
let ks = FixedArray::make(64, b'\x00')
while off < n {
  chacha20_block(key, nonce, ctr, ks, 0)
  ...
}
```

`ks` is allocated once and overwritten each iteration. After the
loop, the final block's keystream remains in `ks` until the
`FixedArray` goes out of scope. The last keystream block is
key-and-nonce-derived secret material — anyone with heap-read
access during the brief window between loop exit and GC sees one
ChaCha20 block worth of secret. Same hygiene point as #7 / #8 /
#9.

**Recommendation**: After the loop, `for i in 0..<64 { ks[i] =
b'\x00' }` before the function returns. One-line, negligible
perf cost.

---

## Info (re-confirmation of correctness or accepted trade-offs)

| # | Item | Note |
|---|---|---|
| 19 | SHA-256 round constants and H0 | Match FIPS 180-4 verbatim. Verified all 64 K[i] + 8 H0[i]. |
| 20 | SHA-512 round constants and H0 | Match FIPS 180-4 verbatim. Verified all 80 K[i] + 8 H0[i]. |
| 21 | BLAKE2b IV and sigma schedule | RFC 7693 §2.6 IV + §2.7 sigma[12 rounds]. Verified rounds 0-11 in `argon2.mbt:1015-1901`. Rounds 10/11 correctly re-use sigma from rounds 0/1. |
| 22 | ChaCha20 constants "expand 32-byte k" | `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574` — RFC 8439 §2.3 verbatim. Rotation amounts 16/12/8/7 correct. |
| 23 | AES S-box (256 entries) | Match FIPS 197 §5.1.1 Figure 7. Spot-checked rows 0, 5, 9, f. |
| 24 | AES Rcon table | `00, 01, 02, 04, 08, 10, 20, 40, 80, 1b, 36` — match FIPS 197 §5.2. |
| 25 | AES-256 key schedule extra `SubWord` | Branch `nk > 6 && i % nk == 4` is present at `aes.mbt:187-194` — required for AES-256, correct. |

---

## Cross-cutting observations

1. **Counter wrap on stream ciphers is the highest-impact gap not
   yet covered by review #1.** Both ChaCha20 (256 GiB cap) and
   AES-GCM (64 GiB cap) silently produce repeated keystream past
   their RFC bounds. Two one-line length checks close this.

2. **Memory wipe is uniformly absent.** Every self-impl module
   (pbkdf2 HMAC state, aead one-time key, ed25519 sign-side
   scratch, ChaCha20 keystream scratch) relies on GC for
   secret-buffer cleanup. MoonBit can express manual zeroize on
   `FixedArray[Byte]` and `FixedArray[UInt64]`; the only fully
   un-wipeable secrets are `BigInt` instances inside ed25519
   `sign`. Establishing a convention of "zero before return" on
   the FixedArray-backed secrets would be a single sweep.

3. **Short-circuit hygiene was fixed in `fe_eq` (review #1) but
   reintroduced one layer up** (`ed_points_equal` uses `&&`, and
   sibling functions `point_decompress` y-check and `fe_is_zero`
   still short-circuit). Today every caller of these functions
   feeds public inputs, so this is hygiene rather than a real
   leak — but the OR-XOR pattern is already proven and ports
   trivially.

4. **No fuzz harnesses for the KDF modules.** `aead`, `ed25519`,
   `x25519`, `pem`, `pkix`, `pkcs8`, `asn1` all have
   `*_fuzz_test.mbt`. `pbkdf2`, `argon2`, `scrypt` do not. PBKDF2
   boundary cases (salt_len near 64, dk_len ≡ 0 mod 32, single-
   iteration vs multi-iteration) and Argon2 pass-count behavior
   are uncovered. Adding `pbkdf2_fuzz_test.mbt` that calls the
   function with random parameters and a known reference vector
   would close the gap cheaply.

5. **The self-impl crypto cores are correct.** Round constants,
   IVs, message schedules, padding rules, endianness conventions,
   and counter formats all check out against the respective RFC /
   FIPS specifications. The substantive remaining work is around
   the perimeter (input bounds, counter caps, memory hygiene),
   not the math.
