// Web Push decryption test against the RFC 8291 §5 worked example.

///|
fn wp_hex(s : String) -> Bytes {
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
test "Web Push decrypt RFC 8291 section 5 example" {
  let auth = wp_hex("05305932a1c7eabe13b6cec9fda48882")
  let ua_priv = wp_hex(
    "ab5757a70dd4a53e553a6bbf71ffefea2874ec07a6b379e3c48f895a02dc33de",
  )
  let ua_pub = wp_hex(
    "042571b2becdfde360551aaf1ed0f4cd366c11cebe555f89bcb7b186a53339173168ece2ebe018597bd30479b86e3c8f8eced577ca59187e9246990db682008b0e",
  )
  let body = wp_hex(
    "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0ff297de5b429bba7153d3a4ae0caa091fd425f3b4b5414add8ab37a19c1bbb05cf5cb5b2a2e0562d558635641ec52812c6c8ff42e95ccb86be7cd",
  )
  let pt = @webpush.decrypt(body, ua_priv, ua_pub, auth)
  let want = "When I grow up, I want to be a watermelon"
  let got = StringBuilder::new()
  for i in 0..<pt.length() {
    got.write_char(pt[i].to_int().to_char().unwrap())
  }
  inspect(got.to_string(), content=want)
}

///|
test "Web Push decrypt rejects a tampered ciphertext" {
  let auth = wp_hex("05305932a1c7eabe13b6cec9fda48882")
  let ua_priv = wp_hex(
    "ab5757a70dd4a53e553a6bbf71ffefea2874ec07a6b379e3c48f895a02dc33de",
  )
  let ua_pub = wp_hex(
    "042571b2becdfde360551aaf1ed0f4cd366c11cebe555f89bcb7b186a53339173168ece2ebe018597bd30479b86e3c8f8eced577ca59187e9246990db682008b0e",
  )
  // Flip the final byte (inside the GCM tag).
  let body = wp_hex(
    "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0ff297de5b429bba7153d3a4ae0caa091fd425f3b4b5414add8ab37a19c1bbb05cf5cb5b2a2e0562d558635641ec52812c6c8ff42e95ccb86be7cc",
  )
  let mut rejected = false
  let _ = @webpush.decrypt(body, ua_priv, ua_pub, auth) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}
