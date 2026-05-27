// RFC 8439 ChaCha20-Poly1305 AEAD plus NIST SP 800-38D AES-128/256-GCM.
//
// ChaCha20 stream cipher is implemented locally in chacha20.mbt with a
// fully-inlined double-round (10 iterations × 8 quarter-rounds). Poly1305
// one-time authenticator is implemented here with 5-limb radix-2^26 field
// arithmetic over GF(2^130 - 5); products fit in UInt64. AES (FIPS 197)
// and GCM (NIST SP 800-38D) are implemented in aes.mbt and gcm.mbt.
//
// This code is not constant-time and should not be used where side-channel
// resistance matters: it uses table-based S-box lookups, branching on byte
// values, and variable-time iteration. Use a vetted library for production.
//
// XChaCha20-Poly1305 (RFC draft-irtf-cfrg-xchacha) extends the nonce to 24
// bytes by deriving a per-nonce sub-key with HChaCha20.

///|
pub(all) enum Algorithm {
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
  XChaCha20Poly1305
} derive(Eq, Debug)

///|
pub fn Algorithm::key_size(self : Algorithm) -> Int {
  match self {
    Aes128Gcm => 16
    Aes256Gcm => 32
    ChaCha20Poly1305 => 32
    XChaCha20Poly1305 => 32
  }
}

///|
pub fn Algorithm::nonce_size(self : Algorithm) -> Int {
  match self {
    Aes128Gcm => 12
    Aes256Gcm => 12
    ChaCha20Poly1305 => 12
    XChaCha20Poly1305 => 24
  }
}

///|
pub fn Algorithm::tag_size(_self : Algorithm) -> Int {
  16
}

///|
pub suberror AeadError {
  InvalidTagSize(expected~ : Int, got~ : Int)
  InvalidKeySize(expected~ : Int, got~ : Int)
  InvalidNonceSize(expected~ : Int, got~ : Int)
  CiphertextTooShort
  AuthenticationFailed
  PlaintextTooLong
} derive(Debug)

///|
/// Encrypts `plaintext` with `key`, `nonce`, and additional authenticated
/// data `aad`. The 16-byte authentication tag is appended to the returned
/// ciphertext.
///
/// **The caller is responsible for ensuring that `nonce` is unique per
/// `(key, message)`.** Reusing a nonce under the same key is catastrophic:
/// for ChaCha20-Poly1305 it leaks the XOR of the two plaintexts and lets
/// an attacker recover the Poly1305 key (allowing forgery); for AES-GCM
/// it leaks the GHASH authentication key. Use a real CSPRNG nonce (see
/// `mizchi/getrandom`) or a persisted monotonic counter. See this
/// module's README for the full rules.
pub fn seal(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise AeadError {
  let (ct, tag) = seal_detached(alg, key, nonce, aad, plaintext)
  let total = ct.length() + tag.length()
  Bytes::makei(total, fn(i) {
    if i < ct.length() {
      ct[i]
    } else {
      tag[i - ct.length()]
    }
  })
}

///|
/// Decrypts `ciphertext_with_tag` (ciphertext followed by 16-byte tag) under
/// `key`, `nonce`, and `aad`. Raises `AuthenticationFailed` on tag mismatch.
pub fn open(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_with_tag : Bytes,
) -> Bytes raise AeadError {
  let tag_len = alg.tag_size()
  if ciphertext_with_tag.length() < tag_len {
    raise CiphertextTooShort
  }
  let ct_len = ciphertext_with_tag.length() - tag_len
  let ct = Bytes::makei(ct_len, fn(i) { ciphertext_with_tag[i] })
  let tag = Bytes::makei(tag_len, fn(i) { ciphertext_with_tag[ct_len + i] })
  open_detached(alg, key, nonce, aad, ct, tag)
}

///|
/// Encrypts `plaintext` and returns the ciphertext and 16-byte tag as a
/// detached pair `(ciphertext, tag)`.
///
/// Same nonce-reuse warning as `seal` applies — the caller MUST ensure
/// the nonce is unique per `(key, message)`.
pub fn seal_detached(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  match alg {
    ChaCha20Poly1305 => chacha20_poly1305_seal(key, nonce, aad, plaintext)
    Aes128Gcm => aes_gcm_seal(16, key, nonce, aad, plaintext)
    Aes256Gcm => aes_gcm_seal(32, key, nonce, aad, plaintext)
    XChaCha20Poly1305 => xchacha20_poly1305_seal(key, nonce, aad, plaintext)
  }
}

///|
/// Decrypts `ciphertext` using a detached `tag`. Raises
/// `AuthenticationFailed` on tag mismatch.
pub fn open_detached(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise AeadError {
  match alg {
    ChaCha20Poly1305 => chacha20_poly1305_open(key, nonce, aad, ciphertext, tag)
    Aes128Gcm => aes_gcm_open(16, key, nonce, aad, ciphertext, tag)
    Aes256Gcm => aes_gcm_open(32, key, nonce, aad, ciphertext, tag)
    XChaCha20Poly1305 =>
      xchacha20_poly1305_open(key, nonce, aad, ciphertext, tag)
  }
}

// ─── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────────

///|
fn validate_key_nonce(key : Bytes, nonce : Bytes) -> Unit raise AeadError {
  if key.length() != 32 {
    raise InvalidKeySize(expected=32, got=key.length())
  }
  if nonce.length() != 12 {
    raise InvalidNonceSize(expected=12, got=nonce.length())
  }
}

///|
// ChaCha20 counter must not wrap. RFC 8439 §2.8 caps at 2^32 blocks per
// (key, nonce); with counter starting at 1 the usable cap is (2^32 - 2) * 64
// = ~274 GiB of plaintext. Past that, the counter wraps back through values
// already used for either Poly1305 key generation or earlier blocks, breaking
// confidentiality without nonce reuse being visible to the caller. MoonBit's
// Bytes is Int-indexed (~2 GiB max) so this is unreachable on current
// platforms, but we surface it as PlaintextTooLong should the platform ever
// grow or callers ever feed pre-fused streams.
fn check_chacha20_block_count(plaintext_len : Int) -> Unit raise AeadError {
  if plaintext_len < 0 {
    raise PlaintextTooLong
  }
  let needed_blocks : UInt64 = (plaintext_len.to_uint64() + 63UL) / 64UL
  let max_blocks : UInt64 = (1UL << 32) - 2UL
  if needed_blocks > max_blocks {
    raise PlaintextTooLong
  }
}

///|
fn chacha20_poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  validate_key_nonce(key, nonce)
  check_chacha20_block_count(plaintext.length())
  let otk_fa = poly1305_key_gen_fa(key, nonce)
  let ct = chacha20_xor(key, nonce, 1U, plaintext)
  let tag = poly1305_aead_tag_fa(otk_fa, aad, ct)
  // Best-effort wipe of the one-time Poly1305 key. See review #2 finding 7.
  zeroize_fa_byte(otk_fa)
  (ct, tag)
}

// ─── XChaCha20-Poly1305 AEAD (extended 24-byte nonce) ──────────────────────
//
// RFC draft-irtf-cfrg-xchacha §2.3. Splits the 24-byte nonce into:
//   nonce[0..16]  → HChaCha20 input for sub-key derivation
//   nonce[16..24] → low 8 bytes of the 12-byte ChaCha20-Poly1305 nonce,
//                   prefixed with 4 zero bytes per draft §2.3.

///|
fn xchacha20_poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  if key.length() != 32 {
    raise InvalidKeySize(expected=32, got=key.length())
  }
  if nonce.length() != 24 {
    raise InvalidNonceSize(expected=24, got=nonce.length())
  }
  let nonce16 = Bytes::makei(16, fn(i) { nonce[i] })
  let sub_key = hchacha20(key, nonce16)
  let cha_nonce = Bytes::makei(12, fn(i) {
    if i < 4 {
      b'\x00'
    } else {
      nonce[i - 4 + 16]
    }
  })
  chacha20_poly1305_seal(sub_key, cha_nonce, aad, plaintext)
}

///|
fn xchacha20_poly1305_open(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise AeadError {
  if key.length() != 32 {
    raise InvalidKeySize(expected=32, got=key.length())
  }
  if nonce.length() != 24 {
    raise InvalidNonceSize(expected=24, got=nonce.length())
  }
  let nonce16 = Bytes::makei(16, fn(i) { nonce[i] })
  let sub_key = hchacha20(key, nonce16)
  let cha_nonce = Bytes::makei(12, fn(i) {
    if i < 4 {
      b'\x00'
    } else {
      nonce[i - 4 + 16]
    }
  })
  chacha20_poly1305_open(sub_key, cha_nonce, aad, ciphertext, tag)
}

///|
fn chacha20_poly1305_open(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise AeadError {
  validate_key_nonce(key, nonce)
  check_chacha20_block_count(ciphertext.length())
  if tag.length() != 16 {
    raise InvalidTagSize(expected=16, got=tag.length())
  }
  let otk_fa = poly1305_key_gen_fa(key, nonce)
  let expected_tag = poly1305_aead_tag_fa(otk_fa, aad, ciphertext)
  // Wipe OTK as soon as the tag has been compared; the tag check below
  // does not need the key any more. See review #2 finding 7.
  zeroize_fa_byte(otk_fa)
  if !constant_time_eq(tag, expected_tag) {
    raise AuthenticationFailed
  }
  chacha20_xor(key, nonce, 1U, ciphertext)
}

///|
/// FixedArray-backed one-time Poly1305 key. Returns the first 32 bytes of
/// ChaCha20(key, nonce, counter=0) in a wipe-able buffer so the caller can
/// zero it after tag computation. See review #2 finding 7.
fn poly1305_key_gen_fa(key : Bytes, nonce : Bytes) -> FixedArray[Byte] {
  chacha20_first32_fa(key, nonce)
}

///|
/// Best-effort zero of a `FixedArray[Byte]`. Caller is responsible for
/// invoking this after a secret is no longer needed. MoonBit gives no
/// guarantee against compiler dead-store elimination or GC copies; this
/// merely shortens the window during which the secret is reachable.
fn zeroize_fa_byte(fa : FixedArray[Byte]) -> Unit {
  for i in 0..<fa.length() {
    fa[i] = b'\x00'
  }
}

///|
/// Stream-xor `data` with ChaCha20(key, nonce, counter). Validation of key/
/// nonce length is the caller's responsibility (callers already check, but we
/// re-check inside to keep this safe at module boundary).
fn chacha20_xor(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
  data : Bytes,
) -> Bytes raise AeadError {
  validate_key_nonce(key, nonce)
  chacha20_xor_unchecked(key, nonce, counter, data)
}

///|
fn chacha20_xor_unchecked(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
  data : Bytes,
) -> Bytes {
  chacha20_xor_inner(key, nonce, counter, data)
}

// ─── Poly1305 (5-limb radix-2^26, UInt64) ─────────────────────────────────
//
// RFC 8439 §2.5. The accumulator a and the clamped multiplier r each live as
// five 26-bit limbs at positions 0, 26, 52, 78, 104 (total 130 bits). The
// reduction trick uses 2^130 ≡ 5 (mod 2^130 - 5), so the s[i] = 5*r[i]
// scalars absorb the wrap from cross products i+j ≥ 5.
//
// Per-block work:
//   c0..c4 ← load 16-byte block + high "RFC bit" via overlapped reads
//   a += c
//   a *= r mod p   (carry chain + one fold of overflow*5)
//
// Each limb product (26 + 26 bits ≤ 2^52) and the *5 variant (≤ 2^55) fit in
// UInt64, so any sum of five such products stays well below 2^60. No 128-bit
// arithmetic is required.

///|
fn le32_fa(b : FixedArray[Byte], off : Int) -> UInt64 {
  b[off].to_uint64() |
  (b[off + 1].to_uint64() << 8) |
  (b[off + 2].to_uint64() << 16) |
  (b[off + 3].to_uint64() << 24)
}

///|
/// Load a 16-byte (or shorter) Poly1305 block plus the implicit high "RFC
/// bit" into five 26-bit limbs. `take` is the number of message bytes in this
/// block (1..=16). For partial blocks the buffer is zero-padded internally.
fn poly1305_load_block(
  msg : Bytes,
  off : Int,
  take : Int,
) -> (UInt64, UInt64, UInt64, UInt64, UInt64) {
  let mask26 : UInt64 = 0x3ffffffUL
  if take == 16 {
    fn le32_msg(o : Int) -> UInt64 {
      msg[o].to_uint64() |
      (msg[o + 1].to_uint64() << 8) |
      (msg[o + 2].to_uint64() << 16) |
      (msg[o + 3].to_uint64() << 24)
    }

    let c0 = le32_msg(off) & mask26
    let c1 = (le32_msg(off + 3) >> 2) & mask26
    let c2 = (le32_msg(off + 6) >> 4) & mask26
    let c3 = (le32_msg(off + 9) >> 6) & mask26
    let c4 = (le32_msg(off + 12) >> 8) | (1UL << 24)
    return (c0, c1, c2, c3, c4)
  }
  // Materialize 17 bytes: msg[off..off+take], then 0x01, then zeros.
  let buf = FixedArray::make(17, b'\x00')
  for i in 0..<take {
    buf[i] = msg[off + i]
  }
  buf[take] = b'\x01'

  // Overlap-load five 32-bit words and slice into 26-bit limbs.
  fn le32_buf(o : Int) -> UInt64 {
    buf[o].to_uint64() |
    (buf[o + 1].to_uint64() << 8) |
    (buf[o + 2].to_uint64() << 16) |
    (buf[o + 3].to_uint64() << 24)
  }

  let c0 = le32_buf(0) & mask26
  let c1 = (le32_buf(3) >> 2) & mask26
  let c2 = (le32_buf(6) >> 4) & mask26
  let c3 = (le32_buf(9) >> 6) & mask26
  // c4 covers msg bytes 12..15 (24 bits) + buf[16] in the high byte.
  let c4 = (le32_buf(12) >> 8) | (buf[16].to_uint64() << 24)
  (c0, c1, c2, c3, c4)
}

///|
fn poly1305_load_full_block_fa(
  buf : FixedArray[Byte],
) -> (UInt64, UInt64, UInt64, UInt64, UInt64) {
  fn le32_buf(o : Int) -> UInt64 {
    buf[o].to_uint64() |
    (buf[o + 1].to_uint64() << 8) |
    (buf[o + 2].to_uint64() << 16) |
    (buf[o + 3].to_uint64() << 24)
  }

  let mask26 : UInt64 = 0x3ffffffUL
  let c0 = le32_buf(0) & mask26
  let c1 = (le32_buf(3) >> 2) & mask26
  let c2 = (le32_buf(6) >> 4) & mask26
  let c3 = (le32_buf(9) >> 6) & mask26
  let c4 = (le32_buf(12) >> 8) | (1UL << 24)
  (c0, c1, c2, c3, c4)
}

///|
fn poly1305_absorb_limbs(
  a0_in : UInt64,
  a1_in : UInt64,
  a2_in : UInt64,
  a3_in : UInt64,
  a4_in : UInt64,
  r0 : UInt64,
  r1 : UInt64,
  r2 : UInt64,
  r3 : UInt64,
  r4 : UInt64,
  s1 : UInt64,
  s2 : UInt64,
  s3 : UInt64,
  s4 : UInt64,
  c0 : UInt64,
  c1 : UInt64,
  c2 : UInt64,
  c3 : UInt64,
  c4 : UInt64,
) -> (UInt64, UInt64, UInt64, UInt64, UInt64) {
  let mask26 : UInt64 = 0x3ffffffUL
  let a0 = a0_in + c0
  let a1 = a1_in + c1
  let a2 = a2_in + c2
  let a3 = a3_in + c3
  let a4 = a4_in + c4

  // a *= r mod p
  // d_k = Σ_{i+j ≡ k mod 5} a_i * r_j' where r_j' = r_j or 5*r_j for wrap.
  let d0 = a0 * r0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1
  let d1 = a0 * r1 + a1 * r0 + a2 * s4 + a3 * s3 + a4 * s2
  let d2 = a0 * r2 + a1 * r1 + a2 * r0 + a3 * s4 + a4 * s3
  let d3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * s4
  let d4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0

  // Carry chain.
  let mut c : UInt64 = d0 >> 26
  let mut out0 = d0 & mask26
  let t1 = d1 + c
  c = t1 >> 26
  let mut out1 = t1 & mask26
  let t2 = d2 + c
  c = t2 >> 26
  let out2 = t2 & mask26
  let t3 = d3 + c
  c = t3 >> 26
  let out3 = t3 & mask26
  let t4 = d4 + c
  c = t4 >> 26
  let out4 = t4 & mask26
  // Fold overflow back via *5 once; resulting out0 may exceed 26 bits by ≤ 1.
  out0 = out0 + c * 5UL
  let c2 = out0 >> 26
  out0 = out0 & mask26
  out1 = out1 + c2
  (out0, out1, out2, out3, out4)
}

///|
fn poly1305_finish(
  a0_in : UInt64,
  a1_in : UInt64,
  a2_in : UInt64,
  a3_in : UInt64,
  a4_in : UInt64,
  k4 : UInt64,
  k5 : UInt64,
  k6 : UInt64,
  k7 : UInt64,
) -> Bytes {
  let mask26 : UInt64 = 0x3ffffffUL
  let mut a0 = a0_in
  let mut a1 = a1_in
  let mut a2 = a2_in
  let mut a3 = a3_in
  let mut a4 = a4_in

  // Final carry propagation so each limb is < 2^26 except possibly a4 < 2^27.
  let mut c : UInt64 = a1 >> 26
  a1 = a1 & mask26
  a2 = a2 + c
  c = a2 >> 26
  a2 = a2 & mask26
  a3 = a3 + c
  c = a3 >> 26
  a3 = a3 & mask26
  a4 = a4 + c
  c = a4 >> 26
  a4 = a4 & mask26
  a0 = a0 + c * 5UL
  c = a0 >> 26
  a0 = a0 & mask26
  a1 = a1 + c

  // Conditional subtraction of p = 2^130 - 5.
  let mut g0 = a0 + 5UL
  let mut g1 = a1 + (g0 >> 26)
  g0 = g0 & mask26
  let mut g2 = a2 + (g1 >> 26)
  g1 = g1 & mask26
  let mut g3 = a3 + (g2 >> 26)
  g2 = g2 & mask26
  let g4 = a4 + (g3 >> 26) - (1UL << 26)
  g3 = g3 & mask26
  let mask = (g4 >> 63) - 1UL
  let inv_mask = mask ^ 0xFFFFFFFFFFFFFFFFUL
  a0 = (g0 & mask) | (a0 & inv_mask)
  a1 = (g1 & mask) | (a1 & inv_mask)
  a2 = (g2 & mask) | (a2 & inv_mask)
  a3 = (g3 & mask) | (a3 & inv_mask)
  a4 = (g4 & mask) | (a4 & inv_mask)

  // Reassemble as 128 bits (drop bits ≥ 128 since tag is mod 2^128).
  let f0 = (a0 | (a1 << 26)) & 0xFFFFFFFFUL
  let f1 = ((a1 >> 6) | (a2 << 20)) & 0xFFFFFFFFUL
  let f2 = ((a2 >> 12) | (a3 << 14)) & 0xFFFFFFFFUL
  let f3 = ((a3 >> 18) | (a4 << 8)) & 0xFFFFFFFFUL

  // Add s (otk[16..32]) and write little-endian 16 bytes.
  let mut sum0 = f0 + k4
  let mut sum1 = f1 + k5 + (sum0 >> 32)
  let mut sum2 = f2 + k6 + (sum1 >> 32)
  let mut sum3 = f3 + k7 + (sum2 >> 32)
  sum0 = sum0 & 0xFFFFFFFFUL
  sum1 = sum1 & 0xFFFFFFFFUL
  sum2 = sum2 & 0xFFFFFFFFUL
  sum3 = sum3 & 0xFFFFFFFFUL

  Bytes::makei(16, fn(i) {
    let word = if i < 4 {
      sum0
    } else if i < 8 {
      sum1
    } else if i < 12 {
      sum2
    } else {
      sum3
    }
    let shift = i % 4 * 8
    ((word >> shift) & 0xFFUL).to_int().to_byte()
  })
}

///|
/// FixedArray-backed Poly1305 MAC. `otk` is 32 bytes; r is the first 16 bytes
/// (clamped) and s is the next 16 bytes. The OTK lives in a wipe-able
/// `FixedArray[Byte]` so the caller can zero it after the tag is computed
/// (review #2 finding 7).
#warnings("-unused_value")
fn poly1305_fa(otk : FixedArray[Byte], msg : Bytes) -> Bytes {
  poly1305_core(
    le32_fa(otk, 0),
    le32_fa(otk, 4),
    le32_fa(otk, 8),
    le32_fa(otk, 12),
    le32_fa(otk, 16),
    le32_fa(otk, 20),
    le32_fa(otk, 24),
    le32_fa(otk, 28),
    msg,
  )
}

///|
/// Core Poly1305 implementation. Takes the 8 little-endian 32-bit words of
/// the one-time key already loaded as UInt64. Sharing this lets both the
/// `Bytes` and `FixedArray[Byte]` entry points use the same arithmetic.
fn poly1305_core(
  k0 : UInt64,
  k1 : UInt64,
  k2 : UInt64,
  k3 : UInt64,
  k4 : UInt64,
  k5 : UInt64,
  k6 : UInt64,
  k7 : UInt64,
  msg : Bytes,
) -> Bytes {
  // Split otk into r (clamped) and s, decomposed into 26-bit limbs.
  let mask26 : UInt64 = 0x3ffffffUL
  // Build r as a 128-bit little-endian integer in 4 32-bit pieces, then clamp.
  let r_lo0 = k0 & 0x0fffffffUL
  let r_lo1 = k1 & 0x0ffffffcUL
  let r_lo2 = k2 & 0x0ffffffcUL
  let r_lo3 = k3 & 0x0ffffffcUL
  // Re-pack into 5 26-bit limbs.
  // bits  0..25  → r0 = r_lo0 & 0x3ffffff
  // bits 26..51  → r1 = (r_lo0 >> 26) | (r_lo1 << 6)  & mask26
  // bits 52..77  → r2 = (r_lo1 >> 20) | (r_lo2 << 12) & mask26
  // bits 78..103 → r3 = (r_lo2 >> 14) | (r_lo3 << 18) & mask26
  // bits 104..   → r4 = r_lo3 >> 8
  let r0 = r_lo0 & mask26
  let r1 = ((r_lo0 >> 26) | (r_lo1 << 6)) & mask26
  let r2 = ((r_lo1 >> 20) | (r_lo2 << 12)) & mask26
  let r3 = ((r_lo2 >> 14) | (r_lo3 << 18)) & mask26
  let r4 = r_lo3 >> 8

  // 5*r[1..4] for fast reduction of high-position cross products.
  let s1 = r1 * 5UL
  let s2 = r2 * 5UL
  let s3 = r3 * 5UL
  let s4 = r4 * 5UL

  // Accumulator a (five 26-bit limbs).
  let mut a0 : UInt64 = 0UL
  let mut a1 : UInt64 = 0UL
  let mut a2 : UInt64 = 0UL
  let mut a3 : UInt64 = 0UL
  let mut a4 : UInt64 = 0UL

  let n = msg.length()
  let mut i = 0
  while i < n {
    let take = if n - i >= 16 { 16 } else { n - i }
    let (c0, c1, c2, c3, c4) = poly1305_load_block(msg, i, take)
    let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
      a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
    )
    a0 = na0
    a1 = na1
    a2 = na2
    a3 = na3
    a4 = na4
    i = i + take
  }

  poly1305_finish(a0, a1, a2, a3, a4, k4, k5, k6, k7)
}

///|
/// Tag for ChaCha20-Poly1305 AEAD. mac_data layout (RFC 8439 §2.8):
///   aad || pad16(aad) || ciphertext || pad16(ciphertext)
///   || len(aad) as 64-bit LE || len(ciphertext) as 64-bit LE
///
/// `otk` is a wipe-able `FixedArray[Byte]` (review #2 finding 7).
fn poly1305_aead_tag_fa(
  otk : FixedArray[Byte],
  aad : Bytes,
  ct : Bytes,
) -> Bytes {
  let k0 = le32_fa(otk, 0)
  let k1 = le32_fa(otk, 4)
  let k2 = le32_fa(otk, 8)
  let k3 = le32_fa(otk, 12)
  let k4 = le32_fa(otk, 16)
  let k5 = le32_fa(otk, 20)
  let k6 = le32_fa(otk, 24)
  let k7 = le32_fa(otk, 28)

  let mask26 : UInt64 = 0x3ffffffUL
  let r_lo0 = k0 & 0x0fffffffUL
  let r_lo1 = k1 & 0x0ffffffcUL
  let r_lo2 = k2 & 0x0ffffffcUL
  let r_lo3 = k3 & 0x0ffffffcUL
  let r0 = r_lo0 & mask26
  let r1 = ((r_lo0 >> 26) | (r_lo1 << 6)) & mask26
  let r2 = ((r_lo1 >> 20) | (r_lo2 << 12)) & mask26
  let r3 = ((r_lo2 >> 14) | (r_lo3 << 18)) & mask26
  let r4 = r_lo3 >> 8
  let s1 = r1 * 5UL
  let s2 = r2 * 5UL
  let s3 = r3 * 5UL
  let s4 = r4 * 5UL

  let mut a0 : UInt64 = 0UL
  let mut a1 : UInt64 = 0UL
  let mut a2 : UInt64 = 0UL
  let mut a3 : UInt64 = 0UL
  let mut a4 : UInt64 = 0UL

  let aad_len = aad.length()
  let mut i = 0
  while i + 16 <= aad_len {
    let (c0, c1, c2, c3, c4) = poly1305_load_block(aad, i, 16)
    let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
      a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
    )
    a0 = na0
    a1 = na1
    a2 = na2
    a3 = na3
    a4 = na4
    i = i + 16
  }
  if i < aad_len {
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<(aad_len - i) {
      buf[j] = aad[i + j]
    }
    let (c0, c1, c2, c3, c4) = poly1305_load_full_block_fa(buf)
    let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
      a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
    )
    a0 = na0
    a1 = na1
    a2 = na2
    a3 = na3
    a4 = na4
  }

  let ct_len = ct.length()
  i = 0
  while i + 16 <= ct_len {
    let (c0, c1, c2, c3, c4) = poly1305_load_block(ct, i, 16)
    let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
      a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
    )
    a0 = na0
    a1 = na1
    a2 = na2
    a3 = na3
    a4 = na4
    i = i + 16
  }
  if i < ct_len {
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<(ct_len - i) {
      buf[j] = ct[i + j]
    }
    let (c0, c1, c2, c3, c4) = poly1305_load_full_block_fa(buf)
    let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
      a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
    )
    a0 = na0
    a1 = na1
    a2 = na2
    a3 = na3
    a4 = na4
  }

  let len_block = FixedArray::make(16, b'\x00')
  let aad_len_u = aad_len.to_uint64()
  let ct_len_u = ct_len.to_uint64()
  for j in 0..<8 {
    len_block[j] = ((aad_len_u >> (j * 8)) & 0xFFUL).to_int().to_byte()
    len_block[j + 8] = ((ct_len_u >> (j * 8)) & 0xFFUL).to_int().to_byte()
  }
  let (c0, c1, c2, c3, c4) = poly1305_load_full_block_fa(len_block)
  let (na0, na1, na2, na3, na4) = poly1305_absorb_limbs(
    a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4, c0, c1, c2, c3, c4,
  )
  poly1305_finish(na0, na1, na2, na3, na4, k4, k5, k6, k7)
}

///|
/// Constant-time-ish equality on Bytes. Length is leaked (always: tag length
/// is fixed at 16 per algorithm); contents are compared by OR-accumulating XOR
/// differences so an attacker cannot use early termination as a timing oracle.
/// MoonBit BigInt itself is variable-time, so this is best-effort.
fn constant_time_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}
