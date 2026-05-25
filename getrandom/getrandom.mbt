// Cross-platform OS CSPRNG access.
//
// The FFI boundary delivers Bytes; this file builds the higher-level helpers
// (fill / uint32 / uint64) on top of `ffi_random_bytes`, which each backend
// file is responsible for implementing:
//   - getrandom_js.mbt      : globalThis.crypto.getRandomValues
//   - getrandom_native.mbt  : C stub (arc4random_buf / getrandom(2))

///|
pub suberror GetrandomError {
  Unavailable(String)
  Insufficient
} derive(Show)

///|
pub fn fill(buf : FixedArray[Byte]) -> Unit raise GetrandomError {
  let len = buf.length()
  if len == 0 {
    return
  }
  let b = ffi_random_bytes(len)
  if b.length() < len {
    raise Insufficient
  }
  for i in 0..<len {
    buf[i] = b[i]
  }
}

///|
pub fn bytes(len : Int) -> Bytes raise GetrandomError {
  if len < 0 {
    raise Unavailable("negative length")
  }
  if len == 0 {
    return b""
  }
  let b = ffi_random_bytes(len)
  if b.length() < len {
    raise Insufficient
  }
  b
}

///|
pub fn uint32() -> UInt raise GetrandomError {
  let b = bytes(4)
  b[0].to_uint() |
  (b[1].to_uint() << 8) |
  (b[2].to_uint() << 16) |
  (b[3].to_uint() << 24)
}

///|
pub fn uint64() -> UInt64 raise GetrandomError {
  let b = bytes(8)
  let mut v : UInt64 = 0UL
  for i = 7; i >= 0; i = i - 1 {
    v = (v << 8) | b[i].to_uint64()
  }
  v
}
