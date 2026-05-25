///|
pub suberror GetrandomError {
  Unavailable(String)
  Insufficient
} derive(Show)

///|
pub fn fill(buf : FixedArray[Byte]) -> Unit raise GetrandomError {
  ignore(buf)
  abort("todo: fill buffer with OS CSPRNG bytes")
}

///|
pub fn bytes(len : Int) -> Bytes raise GetrandomError {
  ignore(len)
  abort("todo: allocate and fill bytes from OS CSPRNG")
}

///|
pub fn uint32() -> UInt raise GetrandomError {
  abort("todo: 4-byte random as UInt")
}

///|
pub fn uint64() -> UInt64 raise GetrandomError {
  abort("todo: 8-byte random as UInt64")
}
