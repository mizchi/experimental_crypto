// Property-based fuzz tests. Generate random Bytes via core/quickcheck and
// check two structural invariants:
//   (1) decode_der must not crash on arbitrary input. Garbage in → Asn1Error
//       out is fine; a panic / abort is a bug.
//   (2) Any input that decode_der accepts must re-encode to the exact same
//       bytes. DER is supposed to be a canonical encoding; if we accept
//       something we can't reproduce, the parser is being too lenient.

///|
test "fuzz asn1: decode_der never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    // We don't care about the value, only that the call returns at all.
    let _ = try? @asn1.decode_der(input)
  }
}

///|
test "fuzz asn1: decode_der_all never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = try? @asn1.decode_der_all(input)
  }
}

///|
test "fuzz asn1: any accepted DER round-trips bit-exactly" {
  let n = 500
  let mut accepted = 0
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    match (try? @asn1.decode_der(input)) {
      Err(_) => () // expected for random bytes
      Ok(elem) => {
        accepted = accepted + 1
        let re_encoded = @asn1.encode_der(elem)
        // If the parser was DER-strict, this must be byte-identical.
        assert_eq(
          re_encoded,
          input,
          msg="canonical roundtrip broken on accepted input",
        )
      }
    }
  }
  // Sanity: with random bytes we expect occasional valid TLVs (single-byte
  // primitives like 0x05 0x00 NULL or 0x01 0x01 ... Boolean). If we never
  // accept anything across N samples something is suspicious — but a flaky
  // 0 doesn't fail the test; we just record it.
  let _ = accepted
}

///|
test "fuzz asn1: tag write_tag / read_tag round-trip" {
  // Generate random (UInt, Bool) pairs and check that write_tag followed by
  // read_tag preserves the tag exactly. Restrict number to <= 2^16 so the
  // base-128 encoding stays in a sensible range.
  let n = 200
  for pair in (@quickcheck.samples(n) : Array[(UInt, Bool)]) {
    let (raw_number, constructed) = pair
    let number = raw_number % 65536U
    let tag = @asn1.Tag::universal(number, constructed~)
    let enc = @asn1.Encoder::new()
    @asn1.write_tag(enc, tag)
    let dec = @asn1.Decoder::new(enc.finish())
    let decoded = @asn1.read_tag(dec)
    assert_eq(decoded, tag)
  }
}

///|
test "fuzz asn1: length write_length / read_length round-trip" {
  let n = 300
  for raw_length in (@quickcheck.samples(n) : Array[Int]) {
    // length is non-negative and limited to what our long-form supports
    // (we cap the long form at 4 bytes -> 2^32 - 1, but stay well under).
    let positive = if raw_length < 0 { -raw_length } else { raw_length }
    let length = positive % 1000000
    let enc = @asn1.Encoder::new()
    @asn1.write_length(enc, length)
    let dec = @asn1.Decoder::new(enc.finish())
    let decoded = @asn1.read_length(dec)
    assert_eq(decoded, length)
  }
}

///|
test "fuzz asn1: oid string round-trip via from_string / to_string" {
  // Build a valid dotted-decimal OID string from random arcs, then check
  // that from_string -> to_string returns the same string.
  let n = 100
  for arcs_raw in (@quickcheck.samples(n) : Array[Array[UInt]]) {
    if arcs_raw.length() < 2 {
      continue
    }
    // Coerce arc[0] to {0,1,2} and arc[1] to <40 when arc[0] < 2 to satisfy
    // the OID well-formedness rule (X.660 §3.5).
    let first = arcs_raw[0] % 3U
    let second = if first < 2U {
      arcs_raw[1] % 40U
    } else {
      arcs_raw[1] % 1000U
    }
    let arcs : Array[UInt] = [first, second]
    for i in 2..<arcs_raw.length() {
      // cap to avoid pathological base-128 lengths
      arcs.push(arcs_raw[i] % 1000000U)
    }
    let s_in = arcs_to_string(arcs)
    let oid = @asn1.ObjectIdentifier::from_string(s_in)
    let s_out = oid.to_string()
    assert_eq(s_out, s_in)
  }
}

///|
fn arcs_to_string(arcs : Array[UInt]) -> String {
  let buf = StringBuilder::new()
  let mut first = true
  for a in arcs {
    if not(first) {
      buf.write_char('.')
    }
    buf.write_string(a.to_string())
    first = false
  }
  buf.to_string()
}
