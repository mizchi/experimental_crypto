///|
test "pem: decode_strict accepts canonical encode_simple output" {
  let original = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
  let encoded = @pem.encode_simple("CERTIFICATE", original)
  let block = @pem.decode_strict(encoded)
  assert_eq(block.label, "CERTIFICATE")
  assert_eq(block.data, original)
  assert_eq(block.headers.length(), 0)
}

///|
test "pem: decode_strict rejects unpadded base64" {
  // AAECAwQ -> drop the '=' padding
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ
    #|-----END CERTIFICATE-----
  match (try? @pem.decode_strict(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="strict mode must require padding")
  }
}

///|
test "pem: decode_strict rejects line > 64 chars" {
  // Base64 line of 80 chars (legal base64, but too long for RFC 7468 strict)
  let input =
    #|-----BEGIN DATA-----
    #|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo=
    #|-----END DATA-----
  match (try? @pem.decode_strict(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="strict mode must reject 80-char line")
  }
}

///|
test "pem: decode_strict rejects pre-BEGIN explanatory text" {
  let input =
    #|some random text before the block
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ=
    #|-----END CERTIFICATE-----
  match (try? @pem.decode_strict(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="strict mode must reject pre-BEGIN garbage")
  }
}

///|
test "pem: decode_strict rejects post-END trailing content" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ=
    #|-----END CERTIFICATE-----
    #|some trailing garbage
  match (try? @pem.decode_strict(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="strict mode must reject post-END garbage")
  }
}

///|
test "pem: decode (lax) accepts the same inputs strict rejects" {
  // Lax mode tolerates surrounding text and unpadded base64 (the latter via
  // core/encoding/base64's default lenient behavior).
  let input =
    #|Pre-BEGIN explanatory text.
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ=
    #|-----END CERTIFICATE-----
    #|Trailing notes.
  let block = @pem.decode(input)
  assert_eq(block.label, "CERTIFICATE")
  assert_eq(block.data, b"\x00\x01\x02\x03\x04")
}

///|
test "pem: encode_simple produces canonical block" {
  let out = @pem.encode_simple("CERTIFICATE", b"\x00\x01\x02\x03\x04")
  inspect(
    out,
    content=(
      #|-----BEGIN CERTIFICATE-----
      #|AAECAwQ=
      #|-----END CERTIFICATE-----
      #|
    ),
  )
}

///|
test "pem: encode wraps base64 at 64 chars" {
  let data = Bytes::makei(48, fn(i) { (i % 256).to_byte() })
  let out = @pem.encode_simple("DATA", data)
  let lines = split_into_lines(out)
  assert_eq(lines[1].length(), 64)
  let data2 = Bytes::makei(49, fn(i) { (i % 256).to_byte() })
  let out2 = @pem.encode_simple("DATA", data2)
  let lines2 = split_into_lines(out2)
  assert_eq(lines2[1].length(), 64)
  assert_true(lines2[2].length() > 0 && lines2[2].length() <= 64)
}

///|
test "pem: decode single block" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ=
    #|-----END CERTIFICATE-----
  let block = @pem.decode(input)
  assert_eq(block.label, "CERTIFICATE")
  assert_eq(block.data, b"\x00\x01\x02\x03\x04")
  assert_eq(block.headers.length(), 0)
}

///|
test "pem: decode tolerates CRLF and surrounding whitespace" {
  let input = "  \r\n-----BEGIN PRIVATE KEY-----\r\nAAEC\r\n-----END PRIVATE KEY-----\r\n  "
  let block = @pem.decode(input)
  assert_eq(block.label, "PRIVATE KEY")
  assert_eq(block.data, b"\x00\x01\x02")
}

///|
test "pem: decode multi-block returns all blocks" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAE=
    #|-----END CERTIFICATE-----
    #|-----BEGIN CERTIFICATE-----
    #|AgM=
    #|-----END CERTIFICATE-----
  let blocks = @pem.decode_all(input)
  assert_eq(blocks.length(), 2)
  assert_eq(blocks[0].data, b"\x00\x01")
  assert_eq(blocks[1].data, b"\x02\x03")
}

///|
test "pem: decode_all skips explanatory text between blocks" {
  let input =
    #|Here is a key issued on 2026-05-25.
    #|Validity: 1 year.
    #|-----BEGIN PUBLIC KEY-----
    #|AAECAwQF
    #|-----END PUBLIC KEY-----
    #|That was the key.
  let blocks = @pem.decode_all(input)
  assert_eq(blocks.length(), 1)
  assert_eq(blocks[0].label, "PUBLIC KEY")
}

///|
test "pem: decode preserves headers when present" {
  let input =
    #|-----BEGIN RSA PRIVATE KEY-----
    #|Proc-Type: 4,ENCRYPTED
    #|DEK-Info: AES-256-CBC,1234567890ABCDEF
    #|
    #|AAECAwQ=
    #|-----END RSA PRIVATE KEY-----
  let block = @pem.decode(input)
  assert_eq(block.label, "RSA PRIVATE KEY")
  assert_eq(block.headers.length(), 2)
  assert_eq(block.headers[0].0, "Proc-Type")
  assert_eq(block.headers[0].1, "4,ENCRYPTED")
  assert_eq(block.headers[1].0, "DEK-Info")
  assert_eq(block.data, b"\x00\x01\x02\x03\x04")
}

///|
test "pem: encode roundtrips a block with headers" {
  let block : @pem.PemBlock = {
    label: "RSA PRIVATE KEY",
    data: b"\x00\x01\x02\x03",
    headers: [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", "AES-256-CBC,1234567890ABCDEF"),
    ],
  }
  let encoded = @pem.encode(block)
  let decoded = @pem.decode(encoded)
  assert_eq(decoded.label, block.label)
  assert_eq(decoded.data, block.data)
  assert_eq(decoded.headers.length(), 2)
  assert_eq(decoded.headers[0], block.headers[0])
  assert_eq(decoded.headers[1], block.headers[1])
}

///|
test "pem: decode rejects label mismatch" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAEC
    #|-----END PRIVATE KEY-----
  match (try? @pem.decode(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected LabelMismatch")
  }
}

///|
test "pem: decode rejects missing END marker" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|AAECAwQ=
  match (try? @pem.decode(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected MissingEndMarker")
  }
}

///|
test "pem: decode rejects invalid base64" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|!!!!
    #|-----END CERTIFICATE-----
  match (try? @pem.decode(input)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidBase64")
  }
}

///|
test "pem: encode then decode roundtrip" {
  let data = Bytes::makei(200, fn(i) { (i * 7 % 256).to_byte() })
  let original : @pem.PemBlock = { label: "DATA", data, headers: [] }
  let encoded = @pem.encode(original)
  let decoded = @pem.decode(encoded)
  assert_eq(decoded.data, data)
}

///|
fn split_into_lines(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  for c in s {
    if c == '\n' {
      out.push(buf.to_string())
      buf.reset()
    } else {
      buf.write_char(c)
    }
  }
  let tail = buf.to_string()
  if tail.length() > 0 {
    out.push(tail)
  }
  out
}
