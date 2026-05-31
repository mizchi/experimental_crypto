// Whitebox tests for CipherState invariants that need direct access to the
// (non-pub(all)) nonce field.

///|
test "ATTACK noise: encrypt_with_ad refuses the reserved 2^64-1 nonce" {
  // Noise §5.1: nonce 2^64-1 is reserved and must never encrypt; the party
  // terminates instead of wrapping. Drive a keyed CipherState to that value.
  let cs : CipherState = { key: Bytes::makei(32, fn(_) { b'\x00' }), nonce: MAX_NONCE }
  try cs.encrypt_with_ad(b"", b"payload") catch {
    NonceExhausted => ()
    _ => abort("expected NonceExhausted, got a different error")
  } noraise {
    _ => abort("accepted encryption with the reserved 2^64-1 nonce")
  }
}

///|
test "ATTACK noise: decrypt_with_ad refuses the reserved 2^64-1 nonce" {
  let cs : CipherState = { key: Bytes::makei(32, fn(_) { b'\x00' }), nonce: MAX_NONCE }
  try cs.decrypt_with_ad(b"", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") catch {
    NonceExhausted => ()
    _ => abort("expected NonceExhausted, got a different error")
  } noraise {
    _ => abort("accepted decryption with the reserved 2^64-1 nonce")
  }
}
