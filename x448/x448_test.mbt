// X448 tests cross-checked against Node's crypto X448 (raw keys + DH).

///|
fn xh(s : String) -> Bytes {
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

///|
fn xhex(b : Bytes) -> String {
  let d = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(d.get_char(v >> 4).unwrap())
    sb.write_char(d.get_char(v & 0xf).unwrap())
  }
  sb.to_string()
}

///|
let a_sk : String = "748cde92279fd185e69bf922659306817a30111b6fadeebc51fc34fdc1cc8d14f33f775f73df46a4f401f3ddf96009cb269d320f1f734fa3"

///|
let a_pk : String = "9464e8089376914877c7ea78b50bec519f261a640d164fe52d5c6d8625033e1e8a408c48ae7f06e2c3aafaac1ea9092fe56ac08d13946266"

///|
let b_sk : String = "48b7888afd01624f18bb93bd62d131b121b42480231036481cdffbdc077f255af6ea7d2bc8f7b39534b251d9bf618d7705894dba9b0cc6bb"

///|
let b_pk : String = "4e479755591f70a29bfb7551ef8f6c32943fe0b5000f6afa7caff80ee490eeed831274615ac2e93ba71ef2bd1c2c8a333f7c56bc990ded60"

///|
let shared : String = "89f41098f457c2e69023a3f0fbdda82594f9196714be677061bd4eea94cf0295a6c56a42ad367f9ef97e18e464e64b16ae12c50211897a25"

///|
test "X448 public key derivation matches Node (base point 5)" {
  inspect(xhex(@x448.public_key(xh(a_sk))), content=a_pk)
  inspect(xhex(@x448.public_key(xh(b_sk))), content=b_pk)
}

///|
test "X448 Diffie-Hellman agrees with Node both directions" {
  inspect(xhex(@x448.x448(xh(a_sk), xh(b_pk))), content=shared)
  inspect(xhex(@x448.x448(xh(b_sk), xh(a_pk))), content=shared)
}

///|
test "X448 rejects bad input lengths" {
  inspect(
    (try? @x448.x448(xh("00112233"), @x448.base_point())) is Err(_),
    content="true",
  )
  inspect((try? @x448.x448(xh(a_sk), xh("00112233"))) is Err(_), content="true")
}

// RFC 7748 §5.2 iterated test. Starting from k = u = encodeUCoordinate(5), set
// k, u = X448(k, u), k each round. This exercises a very wide range of field
// values, so it is the canonical stress test for the limb reduction / carry.

///|
fn x448_iterate(rounds : Int) -> String {
  let base = @x448.base_point()
  let mut k = base
  let mut u = base
  for _i in 0..<rounds {
    let r = @x448.x448(k, u) catch { _ => abort("unreachable") }
    u = k
    k = r
  }
  xhex(k)
}

///|
test "X448 RFC 7748 iterated vector (1 iteration)" {
  inspect(
    x448_iterate(1),
    content="3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
  )
}

///|
test "X448 RFC 7748 iterated vector (1000 iterations)" {
  inspect(
    x448_iterate(1000),
    content="aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
  )
}
