// AEAD interop fixture emitter.
//
// Seals a known (key, nonce, aad, plaintext) under each AEAD this library and
// Node's built-in `crypto` both implement (ChaCha20-Poly1305, AES-128-GCM,
// AES-256-GCM) and prints the inputs + ciphertext as hex. `verify.mjs` opens
// each one with Node and checks the plaintext + authentication tag, proving the
// MoonBit `aead` sealing interoperates byte-for-byte with a reference stack.

///|
fn nib(n : Int) -> Char {
  "0123456789abcdef".get_char(n & 0xf).unwrap()
}

///|
fn to_hex(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i in 0..<b.length() {
    let v = b[i].to_int()
    sb.write_char(nib(v >> 4))
    sb.write_char(nib(v))
  }
  sb.to_string()
}

///|
fn emit_aead(
  name : String,
  alg : @aead.Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  pt : Bytes,
) -> Unit {
  let ct = @aead.seal(alg, key, nonce, aad, pt) catch {
    _ => abort("aead seal failed for " + name)
  }
  println("-----BEGIN AEAD " + name + "-----")
  println("KEY=" + to_hex(key))
  println("NONCE=" + to_hex(nonce))
  println("AAD=" + to_hex(aad))
  println("CT=" + to_hex(ct))
  println("PT=" + to_hex(pt))
  println("-----END AEAD " + name + "-----")
}

///|
fn main {
  let pt : Bytes = b"the quick brown fox jumps over the lazy dog"
  let aad : Bytes = b"experimental_crypto interop aad"
  let key32 = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let key16 = Bytes::makei(16, fn(i) { (i + 7).to_byte() })
  let nonce = Bytes::makei(12, fn(i) { (i + 0x30).to_byte() })
  emit_aead(
    "CHACHA20POLY1305",
    @aead.Algorithm::ChaCha20Poly1305,
    key32,
    nonce,
    aad,
    pt,
  )
  emit_aead("AES128GCM", @aead.Algorithm::Aes128Gcm, key16, nonce, aad, pt)
  emit_aead("AES256GCM", @aead.Algorithm::Aes256Gcm, key32, nonce, aad, pt)
}
