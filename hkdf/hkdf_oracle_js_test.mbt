// JS-target oracle PBTs against Node.js `crypto.hkdfSync`.

///|
extern "js" fn node_hkdf_sha256(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes =
  #| (salt, ikm, info, length) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   return new Uint8Array(crypto.hkdfSync("sha256", ikm, salt, info, length))
  #| }

///|
fn cap_bytes(b : Bytes, max_len : Int) -> Bytes {
  if b.length() <= max_len {
    b
  } else {
    Bytes::makei(max_len, fn(i) { b[i] })
  }
}

///|
fn positive_mod(raw : Int, modulus : Int) -> Int {
  let v = if raw < 0 { -raw } else { raw }
  v % modulus
}

///|
test "oracle pbt hkdf: SHA-256 matches Node crypto" {
  let samples : Array[(Bytes, Bytes, Bytes, Int)] = @quickcheck.samples(60)
  for sample in samples {
    let (raw_ikm, raw_salt, raw_info, raw_len) = sample
    let ikm = cap_bytes(raw_ikm, 256)
    let salt = cap_bytes(raw_salt, 128)
    let info = cap_bytes(raw_info, 128)
    let length = positive_mod(raw_len, 200) + 1
    @debug.assert_eq(
      @hkdf.hkdf(Sha256, salt, ikm, info, length),
      node_hkdf_sha256(salt, ikm, info, length),
    )
  }
}
