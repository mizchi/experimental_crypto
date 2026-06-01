// ECDH known-answer tests for P-256, RFC 5903 §8.1 (256-bit Random ECP Group).

///|
fn ecdh_hex(s : String) -> Bytes {
  fn nibble(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else if n >= 0x41 && n <= 0x46 {
      n - 0x41 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    let hi = nibble(s.get_char(i * 2).unwrap())
    let lo = nibble(s.get_char(i * 2 + 1).unwrap())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
fn ecdh_to_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(digits.get_char(v >> 4).unwrap())
    sb.write_char(digits.get_char(v & 0xf).unwrap())
  }
  sb.to_string()
}

// RFC 5903 §8.1 vectors.

///|
let p256_i : String = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"

///|
let p256_gi : String = "04" +
  "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180" +
  "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"

///|
let p256_r : String = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53"

///|
let p256_gr : String = "04" +
  "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63" +
  "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"

///|
let p256_girx : String = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"

///|
test "ECDH P-256 RFC 5903 initiator computes shared from responder public" {
  let i = @p256.PrivateKey::from_bytes(ecdh_hex(p256_i))
  let gr = @p256.PublicKey::from_uncompressed(ecdh_hex(p256_gr))
  let shared = i.ecdh(gr)
  inspect(ecdh_to_hex(shared), content=p256_girx)
}

///|
test "ECDH P-256 RFC 5903 responder computes same shared from initiator public" {
  let r = @p256.PrivateKey::from_bytes(ecdh_hex(p256_r))
  let gi = @p256.PublicKey::from_uncompressed(ecdh_hex(p256_gi))
  let shared = r.ecdh(gi)
  inspect(ecdh_to_hex(shared), content=p256_girx)
}

///|
test "ECDH P-256 derived public keys match RFC 5903" {
  let i = @p256.PrivateKey::from_bytes(ecdh_hex(p256_i))
  inspect(ecdh_to_hex(i.public_key().to_uncompressed()), content=p256_gi)
  let r = @p256.PrivateKey::from_bytes(ecdh_hex(p256_r))
  inspect(ecdh_to_hex(r.public_key().to_uncompressed()), content=p256_gr)
}

///|
test "ECDH P-256 agreement is symmetric for derived keypairs" {
  let i = @p256.PrivateKey::from_bytes(ecdh_hex(p256_i))
  let r = @p256.PrivateKey::from_bytes(ecdh_hex(p256_r))
  let s1 = i.ecdh(r.public_key())
  let s2 = r.ecdh(i.public_key())
  inspect(ecdh_to_hex(s1), content=p256_girx)
  inspect(ecdh_to_hex(s2), content=p256_girx)
}
