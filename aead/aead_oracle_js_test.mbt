// JS-target oracle PBTs against Node.js `crypto` AEAD implementations.

///|
extern "js" fn node_aead_seal(
  alg : String,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes =
  #| (alg, key, nonce, aad, plaintext) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   const cipher = crypto.createCipheriv(alg, key, nonce, { authTagLength: 16 })
  #|   cipher.setAAD(aad)
  #|   const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  #|   const tag = cipher.getAuthTag()
  #|   return new Uint8Array(Buffer.concat([ct, tag]))
  #| }

///|
fn oracle_ensure_length(b : Bytes, target : Int) -> Bytes {
  if b.length() == target {
    b
  } else if b.length() == 0 {
    Bytes::makei(target, fn(_) { b'\x00' })
  } else if b.length() > target {
    Bytes::makei(target, fn(i) { b[i] })
  } else {
    let n = b.length()
    Bytes::makei(target, fn(i) { b[i % n] })
  }
}

///|
fn cap_bytes(b : Bytes, max_len : Int) -> Bytes {
  if b.length() <= max_len {
    b
  } else {
    Bytes::makei(max_len, fn(i) { b[i] })
  }
}

///|
fn check_oracle(moon_alg : @aead.Algorithm, node_alg : String) -> Unit raise {
  let samples : Array[(Bytes, Bytes, Bytes, Bytes)] = @quickcheck.samples(50)
  for sample in samples {
    let (raw_key, raw_nonce, raw_aad, raw_plaintext) = sample
    let key = oracle_ensure_length(raw_key, moon_alg.key_size())
    let nonce = oracle_ensure_length(raw_nonce, moon_alg.nonce_size())
    let aad = cap_bytes(raw_aad, 256)
    let plaintext = cap_bytes(raw_plaintext, 512)
    @debug.assert_eq(
      @aead.seal(moon_alg, key, nonce, aad, plaintext),
      node_aead_seal(node_alg, key, nonce, aad, plaintext),
    )
  }
}

///|
test "oracle pbt aead: AES-128-GCM seal matches Node crypto" {
  check_oracle(@aead.Aes128Gcm, "aes-128-gcm")
}

///|
test "oracle pbt aead: AES-256-GCM seal matches Node crypto" {
  check_oracle(@aead.Aes256Gcm, "aes-256-gcm")
}

///|
test "oracle pbt aead: ChaCha20-Poly1305 seal matches Node crypto" {
  check_oracle(@aead.ChaCha20Poly1305, "chacha20-poly1305")
}
