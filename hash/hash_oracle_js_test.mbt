// JS-target oracle PBTs. These compare the MoonBit implementation against
// Node.js' built-in `crypto` module on quickcheck-generated inputs.

///|
extern "js" fn node_hash(alg : String, data : Bytes) -> Bytes =
  #| (alg, data) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   return new Uint8Array(crypto.createHash(alg).update(data).digest())
  #| }

///|
extern "js" fn node_hmac(alg : String, key : Bytes, data : Bytes) -> Bytes =
  #| (alg, key, data) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   return new Uint8Array(crypto.createHmac(alg, key).update(data).digest())
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
test "oracle pbt hash: SHA-1/SHA-256/SHA-384/SHA-512 match Node crypto" {
  for input in (@quickcheck.samples(80) : Array[Bytes]) {
    let data = cap_bytes(input, 512)
    @debug.assert_eq(@hash.sha1(data), node_hash("sha1", data))
    @debug.assert_eq(@hash.sha256(data), node_hash("sha256", data))
    @debug.assert_eq(@hash.sha384(data), node_hash("sha384", data))
    @debug.assert_eq(@hash.sha512(data), node_hash("sha512", data))
  }
}

///|
test "oracle pbt hash: HMAC-SHA family matches Node crypto" {
  for sample in (@quickcheck.samples(80) : Array[(Bytes, Bytes)]) {
    let (raw_key, raw_msg) = sample
    let key = cap_bytes(raw_key, 256)
    let msg = cap_bytes(raw_msg, 512)
    @debug.assert_eq(@hash.hmac_sha1(key, msg), node_hmac("sha1", key, msg))
    @debug.assert_eq(@hash.hmac_sha256(key, msg), node_hmac("sha256", key, msg))
    @debug.assert_eq(@hash.hmac_sha384(key, msg), node_hmac("sha384", key, msg))
    @debug.assert_eq(@hash.hmac_sha512(key, msg), node_hmac("sha512", key, msg))
  }
}
