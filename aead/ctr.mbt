// AES-CTR (NIST SP 800-38A §6.5) — the Web Crypto `AES-CTR` primitive.
//
// CTR turns the AES block cipher into a stream cipher: it encrypts a sequence
// of counter blocks and XORs the keystream into the data. Encryption and
// decryption are the same operation, so a single `aes_ctr` covers both.
//
// This is the standard full-width counter: the 16-byte `counter` is the initial
// counter block and is incremented as a 128-bit big-endian integer once per
// block. (Web Crypto's `AES-CTR` lets the caller restrict the counter to the
// low `length` bits; pass the full block here and keep messages well under the
// wrap-around to match that safely.)
//
// CTR provides confidentiality only — NO authentication. Prefer `seal`/`open`
// (AES-GCM / ChaCha20-Poly1305) unless you specifically need a raw stream
// cipher, and never reuse a (key, counter) pair across two messages.

///|
fn ctr_increment(block : FixedArray[Byte]) -> Unit {
  // Big-endian +1 across all 16 bytes, with carry.
  let mut i = 15
  while i >= 0 {
    let v = block.unsafe_get(i).to_int() + 1
    block.unsafe_set(i, (v & 0xff).to_byte())
    if v <= 0xff {
      break
    }
    i = i - 1
  }
}

///|
/// AES-CTR over `data` with the given `key` (16/24/32 bytes) and 16-byte
/// initial `counter` block. Returns the keystream XORed with `data` (so the
/// same call decrypts). Raises `InvalidNonceSize` if `counter` is not 16 bytes
/// and `InvalidKeySize` (via the key schedule) for a bad key length.
pub fn aes_ctr(
  key : Bytes,
  counter : Bytes,
  data : Bytes,
) -> Bytes raise AeadError {
  if counter.length() != 16 {
    raise InvalidNonceSize(expected=16, got=counter.length())
  }
  let (rk, nr) = aes_key_schedule(key)
  let n = data.length()
  if n == 0 {
    return b""
  }
  let out = FixedArray::make(n, b'\x00')
  let ctr_buf = FixedArray::makei(16, fn(i) { counter[i] })
  let ks_buf = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i < n {
    aes_encrypt_block_fa(ctr_buf, 0, rk, nr, ks_buf, 0)
    let take = if n - i >= 16 { 16 } else { n - i }
    for j in 0..<take {
      out[i + j] = (data[i + j].to_int() ^ ks_buf.unsafe_get(j).to_int()).to_byte()
    }
    ctr_increment(ctr_buf)
    i = i + take
  }
  Bytes::makei(n, fn(i) { out.unsafe_get(i) })
}
