// RFC 8018 PBKDF2 with PRF = HMAC-<hash>. Built on moonbitlang/x/crypto.hmac.
//
// Only SHA-256 is implemented today: the HMAC builder in x/crypto needs a
// CryptoHasher value, and only SHA-256 / SHA-224 / MD5 / SM3 are wired up
// there. Sha1 / Sha384 / Sha512 are kept in the enum so callers can switch
// over once x/crypto exposes those hashers.

///|
pub(all) enum HashAlg {
  Sha1
  Sha256
  Sha384
  Sha512
} derive(Eq, Show)

///|
pub suberror Pbkdf2Error {
  InvalidIterations
  OutputTooLong
  InvalidLength
  UnsupportedHash(HashAlg)
} derive(Show)

///|
fn output_size(hash : HashAlg) -> Int {
  match hash {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn hmac_compute(
  hash : HashAlg,
  key : Bytes,
  msg : Bytes,
) -> FixedArray[Byte] raise Pbkdf2Error {
  match hash {
    Sha256 => @crypto.hmac(@crypto.SHA256::new(), key[:], msg[:])
    _ => raise UnsupportedHash(hash)
  }
}

///|
pub fn pbkdf2(
  hash : HashAlg,
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes raise Pbkdf2Error {
  if iterations < 1 {
    raise InvalidIterations
  }
  if dk_len < 0 {
    raise InvalidLength
  }
  let h_len = output_size(hash)
  // PBKDF2 caps dk_len at (2^32 - 1) * h_len, but on a 32-bit Int we cap at
  // Int.max which is well under the spec limit.
  let _ = h_len
  let num_blocks = (dk_len + h_len - 1) / h_len
  let out = Buffer()
  for i = 1; i <= num_blocks; i = i + 1 {
    let block = pbkdf2_block(hash, password, salt, iterations, i)
    out.write_bytes(block)
  }
  let raw = out.to_bytes()
  if raw.length() <= dk_len {
    raw
  } else {
    Bytes::makei(dk_len, fn(j) { raw[j] })
  }
}

///|
fn pbkdf2_block(
  hash : HashAlg,
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  index : Int,
) -> Bytes raise Pbkdf2Error {
  // U_1 = HMAC(P, S || INT(index))
  let salt_with_index = Buffer()
  salt_with_index.write_bytes(salt)
  salt_with_index.write_byte(((index >> 24) & 0xFF).to_byte())
  salt_with_index.write_byte(((index >> 16) & 0xFF).to_byte())
  salt_with_index.write_byte(((index >> 8) & 0xFF).to_byte())
  salt_with_index.write_byte((index & 0xFF).to_byte())
  let mut u = hmac_compute(hash, password, salt_with_index.to_bytes())
  let result = FixedArray::make(u.length(), b'\x00')
  for i in 0..<u.length() {
    result[i] = u[i]
  }
  // T = U_1 XOR U_2 XOR ... XOR U_c
  for _ in 1..<iterations {
    let next = hmac_compute(hash, password, fixed_to_bytes(u))
    for i in 0..<next.length() {
      let xored = result[i].to_int() ^ next[i].to_int()
      result[i] = xored.to_byte()
    }
    u = next
  }
  fixed_to_bytes(result)
}

///|
fn fixed_to_bytes(fa : FixedArray[Byte]) -> Bytes {
  Bytes::makei(fa.length(), fn(i) { fa[i] })
}
