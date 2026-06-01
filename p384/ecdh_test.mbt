// ECDH known-answer tests for P-384, RFC 5903 §8.2 (384-bit Random ECP Group).

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

// RFC 5903 §8.2 vectors.

///|
let p384_i : String = "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655" +
  "e35b538041e649ee3faef896783ab194"

///|
let p384_gi : String = "04" +
  "667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6" +
  "de3ac808acb4bdb4c88732aee95f41aa" +
  "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38e" +
  "eb9fcff3c2c947dae69b4c634573a81c"

///|
let p384_r : String = "41cb0779b4bdb85d47846725fbec3c9430fab46cc8dc5060855cc9bda0aa2942" +
  "e0308312916b8ed2960e4bd55a7448fc"

///|
let p384_gr : String = "04" +
  "e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d" +
  "0d1ac43a0336def96fda41d0774a3571" +
  "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1ff" +
  "f83fa40142209dff5eaad96db9e6386c"

///|
let p384_girx : String = "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4" +
  "d603135569b9e9d09cf5d4a270f59746"

///|
test "ECDH P-384 RFC 5903 initiator computes shared from responder public" {
  let i = @p384.PrivateKey::from_bytes(ecdh_hex(p384_i))
  let gr = @p384.PublicKey::from_uncompressed(ecdh_hex(p384_gr))
  inspect(ecdh_to_hex(i.ecdh(gr)), content=p384_girx)
}

///|
test "ECDH P-384 RFC 5903 responder computes same shared from initiator public" {
  let r = @p384.PrivateKey::from_bytes(ecdh_hex(p384_r))
  let gi = @p384.PublicKey::from_uncompressed(ecdh_hex(p384_gi))
  inspect(ecdh_to_hex(r.ecdh(gi)), content=p384_girx)
}

///|
test "ECDH P-384 derived public keys match RFC 5903" {
  let i = @p384.PrivateKey::from_bytes(ecdh_hex(p384_i))
  inspect(ecdh_to_hex(i.public_key().to_uncompressed()), content=p384_gi)
  let r = @p384.PrivateKey::from_bytes(ecdh_hex(p384_r))
  inspect(ecdh_to_hex(r.public_key().to_uncompressed()), content=p384_gr)
}

///|
test "ECDH P-384 agreement is symmetric for derived keypairs" {
  let i = @p384.PrivateKey::from_bytes(ecdh_hex(p384_i))
  let r = @p384.PrivateKey::from_bytes(ecdh_hex(p384_r))
  inspect(ecdh_to_hex(i.ecdh(r.public_key())), content=p384_girx)
  inspect(ecdh_to_hex(r.ecdh(i.public_key())), content=p384_girx)
}
