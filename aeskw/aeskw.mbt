// AES Key Wrap (RFC 3394) — the Web Crypto `AES-KW` primitive and the JOSE
// A128KW/A192KW/A256KW key-management algorithms.
//
// Wraps an integer number of 64-bit blocks (key material) under a key-encrypting
// key (KEK) of 128/192/256 bits, prepending a 64-bit integrity check value
// (the default IV 0xA6A6A6A6A6A6A6A6, RFC 3394 §2.2.3.1). Unwrap verifies that
// check value in (near) constant time and raises on mismatch.

///|
pub suberror AesKwError {
  /// KEK was not 16, 24, or 32 bytes.
  InvalidKekSize(Int)
  /// Plaintext key was not a multiple of 8 bytes, or fewer than 16 bytes.
  InvalidKeySize(Int)
  /// Wrapped blob was not a multiple of 8 bytes, or fewer than 24 bytes.
  InvalidWrappedSize(Int)
  /// The integrity check value did not match after unwrap (RFC 3394 §2.2.2).
  IntegrityCheckFailed
  Aead(@aead.AeadError)
} derive(Debug)

///|
let default_iv : Bytes = b"\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"

///|
fn check_kek(kek : Bytes) -> Unit raise AesKwError {
  let n = kek.length()
  if n != 16 && n != 24 && n != 32 {
    raise InvalidKekSize(n)
  }
}

///|
/// Wrap `key` (a multiple of 8 bytes, at least 16) under `kek` (16/24/32
/// bytes). Returns `key.length() + 8` bytes (RFC 3394 §2.2.1).
pub fn wrap(kek : Bytes, key : Bytes) -> Bytes raise AesKwError {
  check_kek(kek)
  if key.length() % 8 != 0 || key.length() < 16 {
    raise InvalidKeySize(key.length())
  }
  let n = key.length() / 8
  let a = FixedArray::makei(8, fn(i) { default_iv[i] })
  let r = FixedArray::makei(n * 8, fn(i) { key[i] })
  let block_in = FixedArray::make(16, b'\x00')
  for j in 0..<6 {
    for i in 0..<n {
      for kk in 0..<8 {
        block_in[kk] = a[kk]
        block_in[8 + kk] = r[i * 8 + kk]
      }
      let block_bytes = Bytes::makei(16, fn(idx) { block_in[idx] })
      let b = @aead.aes_block_encrypt(kek, block_bytes) catch {
        e => raise Aead(e)
      }
      let t = n * j + i + 1
      for kk in 0..<8 {
        a[kk] = b[kk]
      }
      // XOR the 32-bit counter t into the low 4 bytes of A (big-endian). t is
      // bounded by 6n, which fits in 32 bits for any practical key.
      a[4] = (a[4].to_int() ^ ((t >> 24) & 0xFF)).to_byte()
      a[5] = (a[5].to_int() ^ ((t >> 16) & 0xFF)).to_byte()
      a[6] = (a[6].to_int() ^ ((t >> 8) & 0xFF)).to_byte()
      a[7] = (a[7].to_int() ^ (t & 0xFF)).to_byte()
      for kk in 0..<8 {
        r[i * 8 + kk] = b[8 + kk]
      }
    }
  }
  Bytes::makei(8 + n * 8, fn(idx) { if idx < 8 { a[idx] } else { r[idx - 8] } })
}

///|
/// Unwrap a blob produced by `wrap` (a multiple of 8 bytes, at least 24) under
/// `kek`. Raises `IntegrityCheckFailed` if the embedded check value is wrong.
pub fn unwrap(kek : Bytes, wrapped : Bytes) -> Bytes raise AesKwError {
  check_kek(kek)
  if wrapped.length() < 24 || wrapped.length() % 8 != 0 {
    raise InvalidWrappedSize(wrapped.length())
  }
  let n = wrapped.length() / 8 - 1
  let a = FixedArray::makei(8, fn(i) { wrapped[i] })
  let r = FixedArray::makei(n * 8, fn(i) { wrapped[8 + i] })
  let block_in = FixedArray::make(16, b'\x00')
  let mut j = 5
  while j >= 0 {
    let mut i = n
    while i >= 1 {
      let t = n * j + i
      for kk in 0..<8 {
        block_in[kk] = a[kk]
      }
      block_in[4] = (block_in[4].to_int() ^ ((t >> 24) & 0xFF)).to_byte()
      block_in[5] = (block_in[5].to_int() ^ ((t >> 16) & 0xFF)).to_byte()
      block_in[6] = (block_in[6].to_int() ^ ((t >> 8) & 0xFF)).to_byte()
      block_in[7] = (block_in[7].to_int() ^ (t & 0xFF)).to_byte()
      for kk in 0..<8 {
        block_in[8 + kk] = r[(i - 1) * 8 + kk]
      }
      let block_bytes = Bytes::makei(16, fn(idx) { block_in[idx] })
      let b = @aead.aes_block_decrypt(kek, block_bytes) catch {
        e => raise Aead(e)
      }
      for kk in 0..<8 {
        a[kk] = b[kk]
        r[(i - 1) * 8 + kk] = b[8 + kk]
      }
      i = i - 1
    }
    j = j - 1
  }
  // Constant-time-ish integrity check: OR-accumulate all diffs (no early exit).
  let mut bad = 0
  for kk in 0..<8 {
    bad = bad | (a[kk].to_int() ^ default_iv[kk].to_int())
  }
  if bad != 0 {
    raise IntegrityCheckFailed
  }
  Bytes::makei(n * 8, fn(idx) { r[idx] })
}
