// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.

///|
test "wb encoder length backpatch emits minimal long-form length" {
  let enc = Encoder::new()
  enc.buf.write_byte(b'\x30')
  let patch = reserve_der_length_patch(enc)
  for _ in 0..<130 {
    enc.buf.write_byte(b'\x05')
  }
  finish_der_length_patch(enc, patch)
  let out = enc.finish()
  @debug.assert_eq(out.length(), 133)
  @debug.assert_eq(out[0], b'\x30')
  @debug.assert_eq(out[1], b'\x81')
  @debug.assert_eq(out[2], b'\x82')
  @debug.assert_eq(out[132], b'\x05')
}

///|
test "wb encoder length backpatch handles nested placeholders" {
  let enc = Encoder::new()
  enc.buf.write_byte(b'\x30')
  let outer = reserve_der_length_patch(enc)
  enc.buf.write_byte(b'\x30')
  let inner = reserve_der_length_patch(enc)
  enc.buf.write_byte(b'\x05')
  enc.buf.write_byte(b'\x00')
  finish_der_length_patch(enc, inner)
  finish_der_length_patch(enc, outer)
  @debug.assert_eq(enc.finish(), b"\x30\x04\x30\x02\x05\x00")
}
