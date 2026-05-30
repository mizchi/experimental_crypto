// RFC 5869 HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
// Built on top of mizchi/experimental_crypto/hash, which ships self-contained
// HMAC-SHA-256 / SHA-384 / SHA-512 (and SHA-224 via SHA-256 truncation), so the
// full SHA-2 family is available — TLS 1.3's SHA-384 suites, RFC 5869 §A.x
// SHA-256 vectors, and SHA-512 expansion all work through one code path.

///|
pub(all) enum HashAlg {
  Sha224
  Sha256
  Sha384
  Sha512
} derive(Eq, Debug)

///|
pub suberror HkdfError {
  OutputTooLong
  InvalidLength
} derive(Debug)

///|
pub fn output_size(hash : HashAlg) -> Int {
  match hash {
    Sha224 => 28
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn hmac_compute(hash : HashAlg, key : Bytes, msg : Bytes) -> Bytes {
  match hash {
    Sha256 => @hash.hmac_sha256(key, msg)
    Sha384 => @hash.hmac_sha384(key, msg)
    Sha512 => @hash.hmac_sha512(key, msg)
    // SHA-224 shares SHA-256's compression function and HMAC construction; the
    // only difference is the digest is truncated to 28 bytes. @hash exposes
    // SHA-256 HMAC, so derive SHA-224 HMAC by truncating at output_size().
    Sha224 => truncate(@hash.hmac_sha256(key, msg), output_size(Sha224))
  }
}

///|
fn truncate(b : Bytes, n : Int) -> Bytes {
  if b.length() <= n {
    return b
  }
  Bytes::makei(n, fn(i) { b[i] })
}

///|
pub fn extract(hash : HashAlg, salt : Bytes, ikm : Bytes) -> Bytes {
  let effective_salt = if salt.length() == 0 {
    Bytes::makei(output_size(hash), fn(_) { b'\x00' })
  } else {
    salt
  }
  hmac_compute(hash, effective_salt, ikm)
}

///|
pub fn expand(
  hash : HashAlg,
  prk : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise HkdfError {
  if length < 0 {
    raise InvalidLength
  }
  if length == 0 {
    return b""
  }
  let hash_len = output_size(hash)
  if length > 255 * hash_len {
    raise OutputTooLong
  }
  let n_blocks = @wrap.hkdf_block_count(length, hash_len)
  let buf = Buffer()
  let mut prev = b""
  for counter = 1; counter <= n_blocks; counter = counter + 1 {
    // T(i) = HMAC(PRK, T(i-1) | info | counter)
    let msg_buf = Buffer()
    msg_buf.write_bytes(prev)
    msg_buf.write_bytes(info)
    msg_buf.write_byte(counter.to_byte())
    let t = hmac_compute(hash, prk, msg_buf.to_bytes())
    buf.write_bytes(t)
    prev = t
  }
  truncate(buf.to_bytes(), length)
}

///|
pub fn hkdf(
  hash : HashAlg,
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise HkdfError {
  let prk = extract(hash, salt, ikm)
  expand(hash, prk, info, length)
}
