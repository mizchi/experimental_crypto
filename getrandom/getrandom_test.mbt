// Property-style tests for the OS CSPRNG bridge. Output is non-deterministic
// so we can only check structural invariants: length, "not all the same
// constant", and rough independence between draws.

///|
test "getrandom: bytes() returns the requested length" {
  @debug.assert_eq(@getrandom.bytes(0).length(), 0)
  @debug.assert_eq(@getrandom.bytes(1).length(), 1)
  @debug.assert_eq(@getrandom.bytes(16).length(), 16)
  @debug.assert_eq(@getrandom.bytes(32).length(), 32)
  @debug.assert_eq(@getrandom.bytes(1024).length(), 1024)
}

///|
test "getrandom: fill() writes into a FixedArray" {
  let buf = FixedArray::make(64, b'\x00')
  @getrandom.fill(buf)
  // Sanity: it is essentially impossible for a 64-byte draw from the OS
  // CSPRNG to be all-zero. If this fires, either the backend silently
  // failed or the OS RNG is broken.
  let mut all_zero = true
  for i in 0..<64 {
    if buf[i].to_int() != 0 {
      all_zero = false
      break
    }
  }
  @debug.assert_eq(all_zero, false)
}

///|
test "getrandom: empty buffer is a no-op" {
  let empty = FixedArray::make(0, b'\x00')
  @getrandom.fill(empty)
  @debug.assert_eq(empty.length(), 0)
}

///|
test "getrandom: two draws differ" {
  // Probability of equality for 32 random bytes is ~2^-256, far below any
  // realistic flake budget.
  let a = @getrandom.bytes(32)
  let b = @getrandom.bytes(32)
  assert_true(a != b)
}

///|
test "getrandom: uint32 / uint64 return varying values" {
  let mut seen_different_u32 = false
  let first_u32 = @getrandom.uint32()
  for _ in 0..<8 {
    if @getrandom.uint32() != first_u32 {
      seen_different_u32 = true
      break
    }
  }
  @debug.assert_eq(seen_different_u32, true)

  let mut seen_different_u64 = false
  let first_u64 = @getrandom.uint64()
  for _ in 0..<8 {
    if @getrandom.uint64() != first_u64 {
      seen_different_u64 = true
      break
    }
  }
  @debug.assert_eq(seen_different_u64, true)
}

///|
test "getrandom: rejects negative length" {
  try @getrandom.bytes(-1) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected error for negative length")
  }
}
