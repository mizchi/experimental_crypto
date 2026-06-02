// Ed448 verification tests against RFC 8032 §7.4 vectors.

///|
fn eh(s : String) -> Bytes {
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

// RFC 8032 §7.4 — empty message.

///|
let pk0 : String = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"

///|
let sig0 : String = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"

// RFC 8032 §7.4 — 1-octet message 0x03.

///|
let pk1 : String = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"

///|
let sig1 : String = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"

///|
test "Ed448 verify RFC 8032 empty-message vector" {
  inspect(@ed448.verify(eh(pk0), b"", eh(sig0)), content="true")
}

///|
test "Ed448 verify RFC 8032 1-octet vector (0x03)" {
  inspect(@ed448.verify(eh(pk1), eh("03"), eh(sig1)), content="true")
}

///|
test "Ed448 rejects a tampered message" {
  inspect(@ed448.verify(eh(pk1), eh("04"), eh(sig1)), content="false")
}

///|
test "Ed448 rejects a tampered signature" {
  let s = eh(sig1)
  let bad = Bytes::makei(s.length(), fn(i) {
    if i == 0 {
      (s[i].to_int() ^ 0x01).to_byte()
    } else {
      s[i]
    }
  })
  inspect(@ed448.verify(eh(pk1), eh("03"), bad), content="false")
}

///|
test "Ed448 rejects wrong-length inputs" {
  inspect(@ed448.verify(eh("0011"), b"", eh(sig0)), content="false")
  inspect(@ed448.verify(eh(pk0), b"", eh("0011")), content="false")
}
