// RFC 8439 ChaCha20-Poly1305 AEAD.
//
// ChaCha20 stream cipher is provided by moonbitlang/x/crypto (ChaCha::chacha20
// + transform). Poly1305 one-time authenticator is implemented locally because
// moonbitlang/x does not ship it yet. Field arithmetic for Poly1305 uses
// moonbitlang/core/bigint, which is variable-time; this implementation is NOT
// constant-time and should not be used where side-channel resistance matters.
//
// AES-GCM and XChaCha20-Poly1305 are out of scope and raise UnsupportedAlgorithm.

///|
pub(all) enum Algorithm {
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
  XChaCha20Poly1305
} derive(Eq, Show)

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
  InvalidKeySize(expected~ : Int, got~ : Int)
  InvalidNonceSize(expected~ : Int, got~ : Int)
  CiphertextTooShort
  AuthenticationFailed
  PlaintextTooLong
  UnsupportedAlgorithm(Algorithm)
} derive(Show)

///|
/// Encrypts `plaintext` with `key`, `nonce`, and additional authenticated
/// data `aad`. The 16-byte authentication tag is appended to the returned
/// ciphertext.
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
pub fn seal_detached(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  match alg {
    ChaCha20Poly1305 => chacha20_poly1305_seal(key, nonce, aad, plaintext)
    Aes128Gcm | Aes256Gcm | XChaCha20Poly1305 => raise UnsupportedAlgorithm(alg)
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
    Aes128Gcm | Aes256Gcm | XChaCha20Poly1305 => raise UnsupportedAlgorithm(alg)
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
fn chacha20_poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  validate_key_nonce(key, nonce)
  let otk = poly1305_key_gen(key, nonce)
  let ct = chacha20_xor(key, nonce, 1U, plaintext)
  let tag = poly1305_aead_tag(otk, aad, ct)
  (ct, tag)
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
  if tag.length() != 16 {
    raise AuthenticationFailed
  }
  let otk = poly1305_key_gen(key, nonce)
  let expected_tag = poly1305_aead_tag(otk, aad, ciphertext)
  if !constant_time_eq(tag, expected_tag) {
    raise AuthenticationFailed
  }
  chacha20_xor(key, nonce, 1U, ciphertext)
}

///|
/// One-time Poly1305 key = first 32 bytes of ChaCha20(key, nonce, counter=0).
fn poly1305_key_gen(key : Bytes, nonce : Bytes) -> Bytes {
  let zeros = Bytes::makei(32, fn(_) { b'\x00' })
  chacha20_xor_unchecked(key, nonce, 0U, zeros)
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
  let n = data.length()
  if n == 0 {
    return b""
  }
  // ChaCha::chacha20 takes ByteSource, but the @crypto package expects @bytes-like;
  // pass Bytes slices via [:]. The transform writes into a FixedArray[Byte].
  let cipher = try? @crypto.ChaCha::chacha20(key[:], nonce[:], counter~)
  let cipher = match cipher {
    Ok(c) => c
    Err(_) => abort("ChaCha20 init failed despite validated lengths")
  }
  let out = FixedArray::make(n, b'\x00')
  cipher.transform(data[:], out)
  Bytes::makei(n, fn(i) { out[i] })
}

// ─── Poly1305 ─────────────────────────────────────────────────────────────
//
// RFC 8439 §2.5. 32-byte one-time key split into r (clamped) and s. Accumulator
// is updated as a = ((a + block) * r) mod (2^130 - 5). At the end, tag =
// (a + s) mod 2^128 as 16 little-endian bytes.

///|
let poly1305_prime : BigInt = (BigInt::from_int(1) << 130) - BigInt::from_int(5)

///|
let poly1305_clamp_mask : BigInt = {
  // 0x0ffffffc0ffffffc0ffffffc0fffffff
  let mut v : BigInt = BigInt::from_int(0)
  let bytes : Array[Int] = [
    0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc, 0x0f,
    0xff, 0xff, 0xff,
  ]
  // The constant is conventionally written big-endian for documentation.
  for b in bytes {
    v = (v << 8) + BigInt::from_int(b)
  }
  v
}

///|
let two_pow_128 : BigInt = BigInt::from_int(1) << 128

///|
fn bytes_le_to_bigint(b : Bytes, offset : Int, len : Int) -> BigInt {
  let mut v : BigInt = BigInt::from_int(0)
  for i = len - 1; i >= 0; i = i - 1 {
    v = (v << 8) + BigInt::from_int(b[offset + i].to_int())
  }
  v
}

///|
fn bigint_to_le_bytes_16(v : BigInt) -> Bytes {
  let mask = BigInt::from_int(0xFF)
  let mut x = v
  Bytes::makei(16, fn(_) {
    let byte = (x & mask).to_int() & 0xFF
    x = x >> 8
    byte.to_byte()
  })
}

///|
fn poly1305(otk : Bytes, msg : Bytes) -> Bytes {
  // r = LE(otk[0..16]) & clamp_mask
  let r = bytes_le_to_bigint(otk, 0, 16) & poly1305_clamp_mask
  let s = bytes_le_to_bigint(otk, 16, 16)
  let mut a : BigInt = BigInt::from_int(0)
  let mut i = 0
  let n = msg.length()
  while i < n {
    let take = if n - i >= 16 { 16 } else { n - i }
    // n = LE(block) + 2^(8*take)  (high bit set per RFC 8439 §2.5)
    let mut block_int : BigInt = BigInt::from_int(0)
    for j = take - 1; j >= 0; j = j - 1 {
      block_int = (block_int << 8) + BigInt::from_int(msg[i + j].to_int())
    }
    let high_bit = BigInt::from_int(1) << (8 * take)
    block_int = block_int + high_bit
    a = (a + block_int) * r % poly1305_prime
    i = i + take
  }
  let tag_int = (a + s) % two_pow_128
  bigint_to_le_bytes_16(tag_int)
}

///|
/// Tag for ChaCha20-Poly1305 AEAD. mac_data layout (RFC 8439 §2.8):
///   aad || pad16(aad) || ciphertext || pad16(ciphertext)
///   || len(aad) as 64-bit LE || len(ciphertext) as 64-bit LE
fn poly1305_aead_tag(otk : Bytes, aad : Bytes, ct : Bytes) -> Bytes {
  let aad_pad = (16 - aad.length() % 16) % 16
  let ct_pad = (16 - ct.length() % 16) % 16
  let total = aad.length() + aad_pad + ct.length() + ct_pad + 8 + 8
  let aad_len_off = aad.length() + aad_pad + ct.length() + ct_pad
  let ct_len_off = aad_len_off + 8
  let aad_len = aad.length().to_int64()
  let ct_len = ct.length().to_int64()
  let mac_data = Bytes::makei(total, fn(i) {
    if i < aad.length() {
      aad[i]
    } else if i < aad.length() + aad_pad {
      b'\x00'
    } else if i < aad.length() + aad_pad + ct.length() {
      ct[i - aad.length() - aad_pad]
    } else if i < aad_len_off {
      b'\x00'
    } else if i < ct_len_off {
      // LE 64-bit aad length
      let shift = (i - aad_len_off) * 8
      ((aad_len >> shift) & 0xFFL).to_int().to_byte()
    } else {
      let shift = (i - ct_len_off) * 8
      ((ct_len >> shift) & 0xFFL).to_int().to_byte()
    }
  })
  poly1305(otk, mac_data)
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
