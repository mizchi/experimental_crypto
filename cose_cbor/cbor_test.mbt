// Blackbox tests for `mizchi/cbor`. Vectors taken from RFC 8949 Appendix A.

// --- Unsigned integer encoding -------------------------------------------

///|
test "uint: 0 -> 0x00" {
  inspect(@cose_cbor.encode(Uint(0UL)), content="b\"\\x00\"")
}

///|
test "uint: 1 -> 0x01" {
  inspect(@cose_cbor.encode(Uint(1UL)), content="b\"\\x01\"")
}

///|
test "uint: 10 -> 0x0a" {
  inspect(
    @cose_cbor.encode(Uint(10UL)),
    content=(
      #|b"\x0a"
    ),
  )
}

///|
test "uint: 23 (max 1-byte) -> 0x17" {
  inspect(@cose_cbor.encode(Uint(23UL)), content="b\"\\x17\"")
}

///|
test "uint: 24 -> 0x1818" {
  inspect(@cose_cbor.encode(Uint(24UL)), content="b\"\\x18\\x18\"")
}

///|
test "uint: 25 -> 0x1819" {
  inspect(@cose_cbor.encode(Uint(25UL)), content="b\"\\x18\\x19\"")
}

///|
test "uint: 100 -> 0x1864" {
  inspect(@cose_cbor.encode(Uint(100UL)), content="b\"\\x18d\"")
}

///|
test "uint: 1000 -> 0x1903e8" {
  inspect(@cose_cbor.encode(Uint(1000UL)), content="b\"\\x19\\x03\\xe8\"")
}

///|
test "uint: 1000000 -> 0x1a000f4240" {
  inspect(@cose_cbor.encode(Uint(1000000UL)), content="b\"\\x1a\\x00\\x0fB@\"")
}

///|
test "uint: 1e12 -> 0x1b000000e8d4a51000" {
  inspect(
    @cose_cbor.encode(Uint(1000000000000UL)),
    content="b\"\\x1b\\x00\\x00\\x00\\xe8\\xd4\\xa5\\x10\\x00\"",
  )
}

// --- Negative integer encoding -------------------------------------------

///|
test "nint: -1 -> 0x20" {
  inspect(
    @cose_cbor.encode(Nint(0UL)),
    content=(
      #|b" "
    ),
  )
}

///|
test "nint: -10 -> 0x29" {
  inspect(
    @cose_cbor.encode(Nint(9UL)),
    content=(
      #|b")"
    ),
  )
}

///|
test "nint: -1000 -> 0x3903e7" {
  // -1000 ⇒ n = -1 - (-1000) = 999
  inspect(@cose_cbor.encode(Nint(999UL)), content="b\"9\\x03\\xe7\"")
}

// --- Byte string encoding ------------------------------------------------

///|
test "bytes: empty -> 0x40" {
  inspect(
    @cose_cbor.encode(Bytes(b"")),
    content=(
      #|b"@"
    ),
  )
}

///|
test "bytes: 4 bytes -> 0x44 01020304" {
  inspect(
    @cose_cbor.encode(Bytes(b"\x01\x02\x03\x04")),
    content="b\"D\\x01\\x02\\x03\\x04\"",
  )
}

// --- Text string encoding ------------------------------------------------

///|
test "text: empty -> 0x60" {
  inspect(
    @cose_cbor.encode(Text("")),
    content=(
      #|b"`"
    ),
  )
}

///|
test "text: IETF -> 0x6449455446" {
  inspect(@cose_cbor.encode(Text("IETF")), content="b\"dIETF\"")
}

///|
test "text: a -> 0x6161" {
  inspect(@cose_cbor.encode(Text("a")), content="b\"aa\"")
}

// --- Array encoding ------------------------------------------------------

///|
test "array: [] -> 0x80" {
  inspect(@cose_cbor.encode(Array([])), content="b\"\\x80\"")
}

///|
test "array: [1,2,3] -> 0x83010203" {
  inspect(
    @cose_cbor.encode(Array([Uint(1UL), Uint(2UL), Uint(3UL)])),
    content="b\"\\x83\\x01\\x02\\x03\"",
  )
}

// --- Map encoding --------------------------------------------------------

///|
test "map: {} -> 0xa0" {
  inspect(@cose_cbor.encode(Map([])), content="b\"\\xa0\"")
}

///|
test "map: {1:2,3:4} -> 0xa201020304" {
  inspect(
    @cose_cbor.encode(Map([(Uint(1UL), Uint(2UL)), (Uint(3UL), Uint(4UL))])),
    content="b\"\\xa2\\x01\\x02\\x03\\x04\"",
  )
}

// --- Simple-value encoding ----------------------------------------------

///|
test "simple: false -> 0xf4" {
  inspect(@cose_cbor.encode(Bool(false)), content="b\"\\xf4\"")
}

///|
test "simple: true -> 0xf5" {
  inspect(@cose_cbor.encode(Bool(true)), content="b\"\\xf5\"")
}

///|
test "simple: null -> 0xf6" {
  inspect(@cose_cbor.encode(Null), content="b\"\\xf6\"")
}

///|
test "simple: undefined -> 0xf7" {
  inspect(@cose_cbor.encode(Undefined), content="b\"\\xf7\"")
}

// --- Tag encoding --------------------------------------------------------

///|
test "tag: 0 + text (RFC 8949 §A standard date-time)" {
  // tag(0, "2013-03-21T20:04:00Z") -> 0xc074 32303133...
  let v = @cose_cbor.encode(Tag(0UL, Text("2013-03-21T20:04:00Z")))
  inspect(v, content="b\"\\xc0t2013-03-21T20:04:00Z\"")
}

///|
test "tag: 18 wraps array (COSE_Sign1 outer tag)" {
  // tag(18, [h'', {}, null, h''])
  let v = @cose_cbor.encode(
    Tag(18UL, Array([Bytes(b""), Map([]), Null, Bytes(b"")])),
  )
  inspect(
    v,
    content=(
      #|b"\xd2\x84@\xa0\xf6@"
    ),
  )
}

// --- Roundtrip tests -----------------------------------------------------

///|
test "decode: roundtrip uint" {
  let original : @cose_cbor.CborValue = Uint(1000000UL)
  let encoded = @cose_cbor.encode(original)
  let decoded = @cose_cbor.decode(encoded)
  match decoded {
    Uint(n) => @debug.assert_eq(n, 1000000UL)
    _ => abort("expected Uint")
  }
}

///|
test "decode: roundtrip nint" {
  let original : @cose_cbor.CborValue = Nint(999UL)
  let decoded = @cose_cbor.decode(@cose_cbor.encode(original))
  match decoded {
    Nint(n) => @debug.assert_eq(n, 999UL)
    _ => abort("expected Nint")
  }
}

///|
test "decode: roundtrip bytes" {
  let encoded = @cose_cbor.encode(Bytes(b"\xde\xad\xbe\xef"))
  let decoded = @cose_cbor.decode(encoded)
  match decoded {
    Bytes(b) => @debug.assert_eq(b, b"\xde\xad\xbe\xef")
    _ => abort("expected Bytes")
  }
}

///|
test "decode: roundtrip text" {
  let encoded = @cose_cbor.encode(Text("hello 世界"))
  let decoded = @cose_cbor.decode(encoded)
  match decoded {
    Text(s) => @debug.assert_eq(s, "hello 世界")
    _ => abort("expected Text")
  }
}

///|
test "decode: roundtrip nested array+map" {
  let original : @cose_cbor.CborValue = Array([
    Map([(Text("a"), Uint(1UL)), (Text("b"), Array([Uint(2UL), Uint(3UL)]))]),
    Bool(true),
    Null,
  ])
  let encoded = @cose_cbor.encode(original)
  let decoded = @cose_cbor.decode(encoded)
  match decoded {
    Array(items) => {
      @debug.assert_eq(items.length(), 3)
      match items[1] {
        Bool(b) => assert_true(b)
        _ => abort("items[1] not bool")
      }
      match items[2] {
        Null => ()
        _ => abort("items[2] not null")
      }
    }
    _ => abort("expected Array")
  }
}

///|
test "decode: tag 0 date-time" {
  let bytes = b"\xc0t2013-03-21T20:04:00Z"
  let decoded = @cose_cbor.decode(bytes)
  match decoded {
    Tag(t, inner) => {
      @debug.assert_eq(t, 0UL)
      match inner {
        Text(s) => @debug.assert_eq(s, "2013-03-21T20:04:00Z")
        _ => abort("inner not text")
      }
    }
    _ => abort("expected Tag")
  }
}

///|
test "decode: trailing bytes raises" {
  let r = try? @cose_cbor.decode(b"\x00\x00")
  match r {
    Err(TrailingBytes(n)) => @debug.assert_eq(n, 1)
    _ => abort("expected TrailingBytes(1)")
  }
}

///|
test "decode: truncated input raises" {
  let r = try? @cose_cbor.decode(b"\x18")
  match r {
    Err(TruncatedInput) => ()
    _ => abort("expected TruncatedInput")
  }
}

///|
test "decode: indefinite length raises" {
  // 0x5f is bytes / indefinite-length start
  let r = try? @cose_cbor.decode(b"\x5f\x40\xff")
  match r {
    Err(IndefiniteLengthUnsupported) => ()
    _ => abort("expected IndefiniteLengthUnsupported")
  }
}

// --- map_get_int helper --------------------------------------------------

///|
test "map_get_int: positive key hit" {
  let m : @cose_cbor.CborValue = Map([
    (Uint(1UL), Text("alpha")),
    (Uint(2UL), Text("beta")),
  ])
  let r = @cose_cbor.map_get_int(m, 2L)
  match r {
    Some(Text(s)) => @debug.assert_eq(s, "beta")
    _ => abort("expected Some(Text(\"beta\"))")
  }
}

///|
test "map_get_int: negative key hit" {
  // COSE alg labels: protected_header[1] = -7 (ES256)
  let m : @cose_cbor.CborValue = Map([(Uint(1UL), Nint(6UL))])
  // Key 1 → Nint(6) which is -7
  let r = @cose_cbor.map_get_int(m, 1L)
  match r {
    Some(Nint(n)) => @debug.assert_eq(n, 6UL)
    _ => abort("expected Nint(6)")
  }
}

///|
test "map_get_int: miss returns None" {
  let m : @cose_cbor.CborValue = Map([(Uint(1UL), Text("x"))])
  match @cose_cbor.map_get_int(m, 99L) {
    None => ()
    _ => abort("expected None")
  }
}

///|
test "map_get_int: nint key" {
  // Map keyed by negative integers (COSE EC2 x/y keys: -2 and -3).
  let m : @cose_cbor.CborValue = Map([
    (Nint(1UL), Bytes(b"\x01")), // key -2
    (Nint(2UL), Bytes(b"\x02")), // key -3
  ])
  match @cose_cbor.map_get_int(m, -3L) {
    Some(Bytes(b)) => @debug.assert_eq(b, b"\x02")
    _ => abort("expected Bytes(\"\\x02\")")
  }
}
