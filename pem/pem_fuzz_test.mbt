// Property-based fuzz tests for the pem module. We only call public API and
// check robustness invariants:
//   (1) decode / decode_all must never panic on arbitrary String input.
//       A PemError is fine; an abort is a bug.
//   (2) Any block we successfully decode must round-trip through encode →
//       decode and produce the same label / data / headers.
//   (3) encode_simple followed by decode must recover the original data bytes
//       (label is sanitised to non-empty single line by the caller).

///|
test "fuzz pem: decode never panics on random strings" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[String]) {
    let _ = try? @pem.decode(input)
  }
}

///|
test "fuzz pem: decode_all never panics on random strings" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[String]) {
    let _ = try? @pem.decode_all(input)
  }
}

///|
test "fuzz pem: accepted block round-trips through encode/decode" {
  let n = 300
  let mut accepted = 0
  for input in (@quickcheck.samples(n) : Array[String]) {
    match (try? @pem.decode(input)) {
      Err(_) => () // expected for random strings
      Ok(block) => {
        accepted = accepted + 1
        let re = @pem.encode(block)
        let decoded = try? @pem.decode(re)
        match decoded {
          Ok(block2) =>
            assert_eq(
              block2,
              block,
              msg="pem roundtrip broken on accepted input",
            )
          Err(e) =>
            // Re-encoded output should always be decodable again.
            fail("re-encoded pem failed to decode: \{e}")
        }
      }
    }
  }
  let _ = accepted
}

///|
test "fuzz pem: encode_simple → decode preserves data" {
  let n = 100
  let pairs : Array[(String, Bytes)] = @quickcheck.samples(n)
  for pair in pairs {
    let (raw_label, data) = pair
    // Sanitise label: encode_simple expects a single-line label.
    // Replace anything outside printable ASCII (excluding '-') with 'X', and
    // fall back to a default if the cleaned label is empty.
    let buf = StringBuilder::new()
    for ch in raw_label {
      let c = ch.to_int()
      if c >= 0x41 && c <= 0x5A {
        buf.write_char(ch) // A-Z
      } else if c >= 0x61 && c <= 0x7A {
        buf.write_char(ch) // a-z
      } else if c >= 0x30 && c <= 0x39 {
        buf.write_char(ch) // 0-9
      } else if c == 0x20 {
        buf.write_char(ch) // space
      }
    }
    let cleaned = buf.to_string()
    let label = if cleaned.length() == 0 { "TEST DATA" } else { cleaned }
    let encoded = @pem.encode_simple(label, data)
    let block = @pem.decode(encoded)
    assert_eq(block.data, data, msg="encode_simple/decode data mismatch")
    assert_eq(block.label, label, msg="encode_simple/decode label mismatch")
  }
}
