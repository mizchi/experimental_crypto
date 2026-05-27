// JS-target oracle PBTs against Node.js `crypto.scryptSync`.

///|
extern "js" fn node_scrypt(
  password : Bytes,
  salt : Bytes,
  log_n : Int,
  r : Int,
  p : Int,
  dk_len : Int,
) -> Bytes =
  #| (password, salt, logN, r, p, dkLen) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   const N = 1 << logN
  #|   return new Uint8Array(crypto.scryptSync(password, salt, dkLen, {
  #|     N,
  #|     r,
  #|     p,
  #|     maxmem: 64 * 1024 * 1024,
  #|   }))
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
test "oracle pbt scrypt: derive_key matches Node crypto" {
  let samples : Array[(Bytes, Bytes, Int)] = @quickcheck.samples(20)
  for sample in samples {
    let (raw_password, raw_salt, raw) = sample
    let password = cap_bytes(raw_password, 64)
    let salt = cap_bytes(raw_salt, 64)
    // Keep oracle PBT cheap: N in {16,32,64}, r in {1,2}, p in {1,2},
    // dk_len in [1,64].
    let log_n = 4 + positive_mod(raw, 3)
    let r = 1 + positive_mod(raw / 3, 2)
    let p = 1 + positive_mod(raw / 5, 2)
    let dk_len = 1 + positive_mod(raw / 7, 64)
    let params : @scrypt.Params = { log_n, r, p, dk_len }
    @debug.assert_eq(
      @scrypt.derive_key(params, password, salt),
      node_scrypt(password, salt, log_n, r, p, dk_len),
    )
  }
}
