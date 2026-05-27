// JS-target oracle PBTs against Node.js `crypto.pbkdf2Sync`.

///|
extern "js" fn node_pbkdf2(
  digest : String,
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes =
  #| (digest, password, salt, iterations, dkLen) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   return new Uint8Array(crypto.pbkdf2Sync(password, salt, iterations, dkLen, digest))
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
test "oracle pbt pbkdf2: SHA-1/SHA-256/SHA-384/SHA-512 match Node crypto" {
  let samples : Array[(Bytes, Bytes, Int)] = @quickcheck.samples(40)
  for sample in samples {
    let (raw_password, raw_salt, raw) = sample
    let password = cap_bytes(raw_password, 128)
    let salt = cap_bytes(raw_salt, 128)
    let iterations = positive_mod(raw, 32) + 1
    let dk_len = positive_mod(raw / 7, 96) + 1
    @debug.assert_eq(
      @pbkdf2.pbkdf2(Sha1, password, salt, iterations, dk_len),
      node_pbkdf2("sha1", password, salt, iterations, dk_len),
    )
    @debug.assert_eq(
      @pbkdf2.pbkdf2(Sha256, password, salt, iterations, dk_len),
      node_pbkdf2("sha256", password, salt, iterations, dk_len),
    )
    @debug.assert_eq(
      @pbkdf2.pbkdf2(Sha384, password, salt, iterations, dk_len),
      node_pbkdf2("sha384", password, salt, iterations, dk_len),
    )
    @debug.assert_eq(
      @pbkdf2.pbkdf2(Sha512, password, salt, iterations, dk_len),
      node_pbkdf2("sha512", password, salt, iterations, dk_len),
    )
  }
}
