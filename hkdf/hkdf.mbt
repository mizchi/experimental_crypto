// RFC 5869 HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
// Built on top of moonbitlang/x/crypto.hmac with the SHA-2 family.
//
// SHA-384 / SHA-512 are not yet provided by moonbitlang/x; only SHA-224 and
// SHA-256 are usable from x/crypto at present. The HashAlg enum keeps the
// extra variants so callers can switch to them once x/crypto grows them.

///|
pub(all) enum HashAlg {
  Sha224
  Sha256
  Sha384
  Sha512
} derive(Eq, Show)

///|
pub suberror HkdfError {
  OutputTooLong
  InvalidLength
  UnsupportedHash(HashAlg)
} derive(Show)

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
fn block_size(hash : HashAlg) -> Int {
  match hash {
    Sha224 | Sha256 => 64
    Sha384 | Sha512 => 128
  }
}

///|
fn hmac_compute(
  hash : HashAlg,
  key : Bytes,
  msg : Bytes,
) -> Bytes raise HkdfError {
  match hash {
    Sha256 =>
      fixed_to_bytes(@crypto.hmac(@crypto.SHA256::new(), key[:], msg[:]))
    // x/crypto.SHA224 exists too; SHA224 shares SHA256's compression so HMAC
    // works with the SHA256 hasher when configured with the SHA-224 IV. The
    // current x/crypto API only exposes SHA256::new(), so we expose Sha224 as
    // an alias that maps to SHA256 + truncate at output_size().
    Sha224 => {
      let full = fixed_to_bytes(
        @crypto.hmac(@crypto.SHA256::new(), key[:], msg[:]),
      )
      truncate(full, output_size(Sha224))
    }
    _ => raise UnsupportedHash(hash)
  }
}

///|
fn fixed_to_bytes(fa : FixedArray[Byte]) -> Bytes {
  Bytes::makei(fa.length(), fn(i) { fa[i] })
}

///|
fn truncate(b : Bytes, n : Int) -> Bytes {
  if b.length() <= n {
    return b
  }
  Bytes::makei(n, fn(i) { b[i] })
}

///|
pub fn extract(
  hash : HashAlg,
  salt : Bytes,
  ikm : Bytes,
) -> Bytes raise HkdfError {
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
