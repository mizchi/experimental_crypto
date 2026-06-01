// AES-CTR known-answer tests, NIST SP 800-38A §F.5 (AES-128/256-CTR).
// Reuses the `ag_hex` / `ag_to_hex` helpers from aes_gcm_test.mbt.

///|
let ctr_iv : String = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

///|
let ctr_pt : String = "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710"

///|
test "AES-128-CTR NIST SP 800-38A F.5.1/F.5.2" {
  let key = ag_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let ct = @aead.aes_ctr(key, ag_hex(ctr_iv), ag_hex(ctr_pt))
  inspect(
    ag_to_hex(ct),
    content="874d6191b620e3261bef6864990db6ce" +
      "9806f66b7970fdff8617187bb9fffdff" +
      "5ae4df3edbd5d35e5b4f09020db03eab" +
      "1e031dda2fbe03d1792170a0f3009cee",
  )
  // CTR is symmetric: encrypting the ciphertext recovers the plaintext.
  inspect(ag_to_hex(@aead.aes_ctr(key, ag_hex(ctr_iv), ct)), content=ctr_pt)
}

///|
test "AES-256-CTR NIST SP 800-38A F.5.5/F.5.6" {
  let key = ag_hex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  )
  let ct = @aead.aes_ctr(key, ag_hex(ctr_iv), ag_hex(ctr_pt))
  inspect(
    ag_to_hex(ct),
    content="601ec313775789a5b7a7f504bbf3d228" +
      "f443e3ca4d62b59aca84e990cacaf5c5" +
      "2b0930daa23de94ce87017ba2d84988d" +
      "dfc9c58db67aada613c2dd08457941a6",
  )
}

///|
test "AES-CTR counter carries across a byte boundary" {
  // Counter 0x...ff increments to 0x...0100 over two blocks; cross-check the
  // two-block stream against two independent single-block CTR calls.
  let key = ag_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let ctr0 = ag_hex("000000000000000000000000000000ff")
  let ctr1 = ag_hex("00000000000000000000000000000100")
  let zero16 = ag_hex("00000000000000000000000000000000")
  let zero32 = ag_hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let two = @aead.aes_ctr(key, ctr0, zero32)
  let b0 = @aead.aes_ctr(key, ctr0, zero16)
  let b1 = @aead.aes_ctr(key, ctr1, zero16)
  // First keystream block uses ctr0, second uses ctr1 (post-carry).
  let two_hex = ag_to_hex(two)
  inspect(two_hex[0:32].to_owned(), content=ag_to_hex(b0))
  inspect(two_hex[32:64].to_owned(), content=ag_to_hex(b1))
}

///|
test "AES-CTR rejects a non-16-byte counter" {
  let key = ag_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let mut rejected = false
  let _ = @aead.aes_ctr(key, ag_hex("00112233"), b"hello") catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}
