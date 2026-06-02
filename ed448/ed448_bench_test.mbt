// Benchmark for Ed448 verification. verify does a double scalar multiplication
// ([S]B and [k]A) in projective coordinates over @bigint, plus a SHAKE256 hash —
// the scalar mults (each ~446 unified adds with field mul/sq) dominate.

///|
fn bh(s : String) -> Bytes {
  fn nib(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((nib(s.get_char(i * 2).unwrap()) << 4) |
    nib(s.get_char(i * 2 + 1).unwrap())).to_byte()
  }
  Bytes::makei(len, fn(j) { out[j] })
}

// RFC 8032 §7.4 — 1-octet message 0x03.

///|
let bench_pk : String = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"

///|
let bench_sig : String = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"

///|
test "bench ed448 verify (RFC 8032 1-octet vector)" (it : @bench.T) {
  let pk = bh(bench_pk)
  let msg = bh("03")
  let sig = bh(bench_sig)
  it.bench(name="ed448 verify", count=20, () => {
    it.keep(@ed448.verify(pk, msg, sig))
  })
}
