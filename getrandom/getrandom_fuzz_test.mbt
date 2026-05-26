// Property-based fuzz tests for the OS CSPRNG bridge. quickcheck feeds us
// arbitrary lengths and we check structural invariants:
//   (1) bytes(n) returns exactly n bytes for any positive n.
//   (2) fill(buf) actually overwrites the buffer — every byte staying at the
//       sentinel 0xAA across a 4+ byte draw has probability ~ 2^(-32) per
//       run, well below any realistic flake budget.
//   (3) Two independent 32-byte draws differ with overwhelming probability
//       (~2^-256 of collision).
//   (4) uint32() across 64 draws exhibits both LSB=0 and LSB=1 outcomes
//       (failure probability 2^-63 per direction).

///|
test "fuzz getrandom: bytes(n) returns exactly n bytes" {
  for raw_n in (@quickcheck.samples(50) : Array[Int]) {
    let positive = if raw_n < 0 { -raw_n } else { raw_n }
    let n = positive % 1024 + 1
    let b = @getrandom.bytes(n)
    @debug.assert_eq(b.length(), n)
  }
}

///|
test "fuzz getrandom: fill writes everything" {
  for raw_n in (@quickcheck.samples(30) : Array[Int]) {
    let positive = if raw_n < 0 { -raw_n } else { raw_n }
    let n = positive % 256 + 1
    let buf = FixedArray::make(n, b'\xAA')
    @getrandom.fill(buf)
    // For n >= 4 the all-0xAA flake rate is ~ 2^(-32) — safe to assert that
    // at least one byte was rewritten.
    if n >= 4 {
      let mut all_same = true
      for i in 0..<n {
        if buf[i] != b'\xAA' {
          all_same = false
          break
        }
      }
      @debug.assert_eq(all_same, false)
    }
  }
}

///|
test "fuzz getrandom: independent 32-byte draws differ" {
  for _ in 0..<20 {
    let a = @getrandom.bytes(32)
    let b = @getrandom.bytes(32)
    assert_true(a != b)
  }
}

///|
test "fuzz getrandom: uint32 has reasonable bit distribution" {
  // Out of 64 draws both LSB=0 and LSB=1 should occur; each direction's
  // failure probability is 2^-63.
  let mut saw_0 = false
  let mut saw_1 = false
  for _ in 0..<64 {
    let v = @getrandom.uint32()
    if (v.reinterpret_as_int() & 1) == 0 {
      saw_0 = true
    } else {
      saw_1 = true
    }
  }
  @debug.assert_eq(saw_0, true)
  @debug.assert_eq(saw_1, true)
}

///|
test "fuzz getrandom: negative length always rejects" {
  for raw_n in (@quickcheck.samples(20) : Array[Int]) {
    let neg = if raw_n > 0 { -raw_n } else if raw_n == 0 { -1 } else { raw_n }
    try @getrandom.bytes(neg) catch {
      _ => ()
    } noraise {
      _ => fail("negative length must reject")
    }
  }
}
